package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func joinParams(t *testing.T, ca testCA, url, dir string) Params {
	t.Helper()
	return Params{
		URL: url, Token: "test-token",
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Extra: map[string]any{
			"region":        "fsn1",
			"agent_version": "1.0.0",
			"addresses":     map[string]any{"private_ip": "10.0.0.5"},
			"capacity":      map[string]any{"cpu_millis": int64(2000), "memory_bytes": int64(1 << 32), "disk_bytes": int64(1 << 36)},
		},
		CertPath: filepath.Join(dir, "node.pem"),
		KeyPath:  filepath.Join(dir, "node-key.pem"),
		CAPEM:    ca.pem,
		Roots:    ca.pool(t),
	}
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestJoinWritesCertificateAndDeletesToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)

	// The key is created before the request — the server signs exactly it.
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("the request body does not parse: %v", err)
		}
		if req["node_id"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
			t.Errorf("node_id = %v", req["node_id"])
		}
		if req["join_token"] != "test-token" {
			t.Errorf("join_token did not arrive")
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	tokenPath := filepath.Join(dir, "join-token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("token: %v", err)
	}
	p.TokenPath = tokenPath

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}

	state, _, _ := Inspect(p.CertPath, ca.pool(t), KindNode, time.Now())
	if state != CertValid {
		t.Fatalf("after the join the certificate is in state %q", state)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatal("the token file has to be deleted after a successful join")
	}
}

// Generalising the payload (plan 03, task 1, step 4): the join body for kind
// node has to stay byte-for-byte what it was before the generalisation to
// kind/cn — node_id, addresses.private_ip and capacity — because executor-1
// will be talking to a CP that also serves the old /v1/nodes/join route
// (control-plane/internal/api/joinrouter.go), which expects exactly that body
// shape.
func TestJoinRequestNodeWireFormatUnchanged(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("the request body does not parse: %v", err)
			return
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}

	if captured["kind"] != "node" {
		t.Fatalf("kind = %v, expected \"node\"", captured["kind"])
	}
	if captured["cn"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
		t.Fatalf("cn = %v", captured["cn"])
	}
	if captured["node_id"] != "n-01j9qk3m7x2v5tpb8w4h6n0zya" {
		t.Fatalf("node_id = %v, expected the previous node_id", captured["node_id"])
	}
	addresses, ok := captured["addresses"].(map[string]any)
	if !ok {
		t.Fatalf("addresses = %v, expected an object", captured["addresses"])
	}
	if addresses["private_ip"] != "10.0.0.5" {
		t.Fatalf("addresses.private_ip = %v", addresses["private_ip"])
	}
	capacity, ok := captured["capacity"].(map[string]any)
	if !ok {
		t.Fatalf("capacity = %v, expected an object", captured["capacity"])
	}
	if capacity["cpu_millis"] != float64(2000) {
		t.Fatalf("capacity.cpu_millis = %v", capacity["cpu_millis"])
	}
	if captured["region"] != "fsn1" {
		t.Fatalf("region = %v", captured["region"])
	}
	if captured["agent_version"] != "1.0.0" {
		t.Fatalf("agent_version = %v", captured["agent_version"])
	}
}

// Step 5 of the plan: buildCSR assembles three different CSR shapes depending
// on the kind of participant. Node and service carry exactly one SAN IP — the
// one in Identity; client carries no SAN IP at all, which is what
// control-plane/internal/pki.ValidateCSR requires for a client leaf.
func TestBuildCSRPerKind(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	cases := []struct {
		name string
		id   Identity
	}{
		{"node carries a SAN IP", Identity{Kind: KindNode, CN: "n-01j9qk3m7x2v5tpb8w4h6n0zya", IP: net.ParseIP("10.0.0.5")}},
		{"service carries a SAN IP", Identity{Kind: KindService, CN: "builder-1", IP: net.ParseIP("10.0.0.9")}},
		{"client carries no SAN IP", Identity{Kind: KindClient, CN: "ops-laptop", IP: nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csrPEM, err := buildCSR(key, c.id)
			if err != nil {
				t.Fatalf("buildCSR: %v", err)
			}
			block, _ := pem.Decode(csrPEM)
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Fatal("the CSR is not PEM")
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("parsing the CSR: %v", err)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("the CSR signature does not check out: %v", err)
			}
			if csr.Subject.CommonName != c.id.CN {
				t.Fatalf("CN = %q, expected %q", csr.Subject.CommonName, c.id.CN)
			}
			if c.id.IP != nil {
				if len(csr.IPAddresses) != 1 || !csr.IPAddresses[0].Equal(c.id.IP) {
					t.Fatalf("IPAddresses = %v, expected exactly [%v]", csr.IPAddresses, c.id.IP)
				}
			} else if len(csr.IPAddresses) != 0 {
				t.Fatalf("IPAddresses = %v, a client has no business carrying a SAN IP", csr.IPAddresses)
			}
		})
	}
}

// Plan 03, task 3, step 0 (a blocking precondition): the Control Plane issues
// a client leaf with clientAuth only (control-plane/internal/pki.SignLeaf),
// while before this test verifyIssuedCert required serverAuth
// unconditionally — a real join of kind client would have fallen over on its
// own side's check, without once getting to the question of who to trust in
// the first place.
func TestJoinAcceptsClientAuthOnlyLeafForClientKind(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := Params{
		Token:    "test-token",
		Identity: Identity{Kind: KindClient, CN: "ops-laptop"},
		CertPath: filepath.Join(dir, "client.pem"),
		KeyPath:  filepath.Join(dir, "client-key.pem"),
		CAPEM:    ca.pem,
		Roots:    ca.pool(t),
	}
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := ca.clientLeafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("a join of kind client with a clientAuth-only leaf has to succeed: %v", err)
	}

	state, _, _ := Inspect(p.CertPath, ca.pool(t), KindClient, time.Now())
	if state != CertValid {
		t.Fatalf("Inspect(kind=client) = %q, expected %q", state, CertValid)
	}
}

// The same fix has no business breaking node: a node/service leaf carries both
// EKUs (serverAuth+clientAuth), and join has to keep passing the serverAuth
// check.
func TestJoinStillAcceptsNodeLeaf(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("a join of kind node has to succeed: %v", err)
	}

	state, _, _ := Inspect(p.CertPath, ca.pool(t), KindNode, time.Now())
	if state != CertValid {
		t.Fatalf("Inspect(kind=node) = %q, expected %q", state, CertValid)
	}
}

// 4xx is fatal: a rejected token will not become an accepted one through
// retries, and a daemon that keeps retrying hides a provisioning error behind
// a green unit.
func TestJoinFatalOn4xx(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"join_denied","message":"no","details":{}}}`))
	}))
	defer srv.Close()

	p := joinParams(t, ca, srv.URL, dir)
	if _, err := LoadOrCreateKey(p.KeyPath); err != nil {
		t.Fatalf("key: %v", err)
	}
	err := Join(context.Background(), p, discardLog())
	if !errors.Is(err, ErrJoinRejected) {
		t.Fatalf("err = %v, expected ErrJoinRejected", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d attempts were made, a 4xx must not be retried", calls.Load())
	}
}

func TestJoinRetriesOn5xx(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	key, _ := LoadOrCreateKey(p.KeyPath)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		leaf := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(ca.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL
	p.Backoff = time.Millisecond // the test must not wait around for seconds

	if err := Join(context.Background(), p, discardLog()); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("%d attempts, expected 3", calls.Load())
	}
}

// A certificate that does not chain to the pinned CA has no business landing
// on disk: otherwise a substituted CP would foist its own identity on the
// participant.
func TestJoinRejectsCertificateFromForeignCA(t *testing.T) {
	ours := makeCA(t)
	foreign := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ours, "", dir)
	key, _ := LoadOrCreateKey(p.KeyPath)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := foreign.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(foreign.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err == nil {
		t.Fatal("a certificate from a foreign CA has to be rejected")
	}
	if _, err := os.Stat(p.CertPath); !os.IsNotExist(err) {
		t.Fatal("a rejected certificate has no business landing on disk")
	}
}

// A certificate can chain honestly to the pinned CA and still be unusable: if
// it was issued for a foreign public key, the participant has no private key
// for it and the TLS handshake will never come up. This branch of installCert
// is separate from the chain check (TestJoinRejectsCertificateFromForeignCA).
func TestJoinRejectsCertificateOnForeignKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	p := joinParams(t, ca, "", dir)
	if _, err := LoadOrCreateKey(p.KeyPath); err != nil {
		t.Fatalf("key: %v", err)
	}

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("foreign key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The right CA (ca), but signed for a key the participant does not have.
		leaf := ca.leafFor(t, &foreignKey.PublicKey, time.Now().Add(time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf), "ca_pem": string(ca.pem)})
	}))
	defer srv.Close()
	p.URL = srv.URL

	if err := Join(context.Background(), p, discardLog()); err == nil {
		t.Fatal("a certificate issued for a foreign key has to be rejected")
	}
	if _, err := os.Stat(p.CertPath); !os.IsNotExist(err) {
		t.Fatal("a rejected certificate has no business landing on disk, even if the chain to the CA is right")
	}
}
