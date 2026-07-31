package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ensureDeps(t *testing.T, dir, mode string) Deps {
	t.Helper()
	return Deps{
		Mode:          mode,
		PKIURL:        "https://10.0.0.3:8444",
		JoinTokenFile: filepath.Join(dir, "join-token"),
		CAFile:        filepath.Join(dir, "ca.pem"),
		CertFile:      filepath.Join(dir, "node.pem"),
		KeyFile:       filepath.Join(dir, "node-key.pem"),
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Extra: map[string]any{
			"region":        "fsn1",
			"agent_version": "1.0.0",
			"addresses":     map[string]any{"private_ip": "10.0.0.5"},
		},
		Log: discardLog(),
		Now: time.Now,
	}
}

func TestEnsureSkipsInWebhookMode(t *testing.T) {
	dir := t.TempDir()
	d := ensureDeps(t, dir, "webhook")
	// No CA, no certificate, no token — and still no error at all: in webhook
	// mode join is skipped entirely (§3.2 of the contract), and a running
	// participant on dev-1 has to survive a rollout of this code.
	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("in webhook mode Ensure has to be a no-op, got: %v", err)
	}
}

func TestEnsureRequiresCAAlways(t *testing.T) {
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "ca.pem") {
		t.Fatalf("a missing pinned CA has to fail the start and name the file, got: %v", err)
	}
}

func TestEnsureSkipsWhenCertificateValid(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	// The key is a full half of the identity: without it a certificate alone
	// is no reason to skip a join (see TestEnsureRejoinsWhenValidCertificateHasNoKey).
	// The key is created BEFORE the certificate and the certificate is signed
	// for exactly its public half (leafFor, not leaf) — otherwise the pair on
	// disk is split by the test's own construction, and with the check that
	// was introduced (C2) Ensure legitimately goes for a join instead of
	// skipping, which is not what this test wants to check.
	key, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	writeFile(t, d.CertFile, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))
	// The token lies next to it and has to SURVIVE the call: silently
	// destroying credentials placed there for a planned re-join is worse than
	// leaving them alone.
	writeFile(t, d.JoinTokenFile, []byte("do-not-touch"))

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Stat(d.JoinTokenFile); err != nil {
		t.Fatal("a token next to a valid certificate has no business being deleted")
	}
}

// The certificate is valid on its own, but without a key it is not an
// identity: TLS will not come up without a private key. Since there is
// something to join with (the token is in place), Ensure has to notice the
// split pair and join again instead of taking one valid-looking file for a
// complete identity and quietly allowing the start — that is exactly how the
// bug from the review reproduced.
func TestEnsureRejoinsWhenValidCertificateHasNoKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	staleCert := ca.leaf(t, time.Now().Add(time.Hour))
	writeFile(t, d.CertFile, staleCert)
	// The key is deliberately not created: there is a certificate and no key
	// for it.
	writeFile(t, d.JoinTokenFile, []byte("test-token"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("the request body does not parse: %v", err)
			return
		}
		csrPEM, _ := req["csr_pem"].(string)
		block, _ := pem.Decode([]byte(csrPEM))
		if block == nil {
			t.Errorf("csr_pem is not PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Errorf("csr_pem does not parse: %v", err)
			return
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("the CSR is not on an EC key")
			return
		}
		leaf := ca.leafFor(t, pub, time.Now().Add(time.Hour))
		if err := json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		}); err != nil {
			t.Errorf("the join response does not write: %v", err)
		}
	}))
	defer srv.Close()
	d.PKIURL = srv.URL

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if _, err := os.Stat(d.KeyFile); err != nil {
		t.Fatal("the missing key has to be created by joining again")
	}
	newCert, err := os.ReadFile(d.CertFile)
	if err != nil {
		t.Fatalf("reading the new certificate: %v", err)
	}
	if string(newCert) == string(staleCert) {
		t.Fatal("the orphaned certificate has to be overwritten by a new one consistent with the key")
	}
	if _, err := os.Stat(d.JoinTokenFile); !os.IsNotExist(err) {
		t.Fatal("the token has to be deleted after a successful re-join")
	}
}

// A direct reproduction of C2 of the final review: the certificate is valid on
// its own, and the key on disk is not the one it belongs to (for example — a
// join once died between writing the new key and receiving the new
// certificate, leaving the old certificate next to the new key). os.Stat used
// to let that pair through because both files existed; the daemon would start
// on and fail at tls.LoadX509KeyPair in the caller, without a single chance at
// a join, even with a fresh token sitting right there. Ensure has to notice
// the mismatch and join again, reusing the key that lies on disk (rather than
// discarding it) — exactly the way the retry path in §6.1.1 does it: Join sees
// the existing key file and signs the CSR with it.
func TestEnsureRejoinsWhenCertificateAndKeyAreMismatched(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	staleCert := ca.leaf(t, time.Now().Add(time.Hour))
	writeFile(t, d.CertFile, staleCert)
	// The key on disk is real and readable, but it is not what this
	// certificate was signed for.
	mismatchedKey, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	writeFile(t, d.JoinTokenFile, []byte("test-token"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("the request body does not parse: %v", err)
			return
		}
		csrPEM, _ := req["csr_pem"].(string)
		block, _ := pem.Decode([]byte(csrPEM))
		if block == nil {
			t.Errorf("csr_pem is not PEM")
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Errorf("csr_pem does not parse: %v", err)
			return
		}
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Errorf("the CSR is not on an EC key")
			return
		}
		// Confirm that the CSR carries the key that was ALREADY on disk rather
		// than some new one: the retry path has to reuse it.
		if !pub.Equal(&mismatchedKey.PublicKey) {
			t.Errorf("the CSR was signed with a different key than the one already on disk")
		}
		leaf := ca.leafFor(t, pub, time.Now().Add(time.Hour))
		if err := json.NewEncoder(w).Encode(map[string]string{
			"cert_pem": string(leaf), "ca_pem": string(ca.pem),
		}); err != nil {
			t.Errorf("the join response does not write: %v", err)
		}
	}))
	defer srv.Close()
	d.PKIURL = srv.URL

	if err := Ensure(context.Background(), d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	newCert, err := os.ReadFile(d.CertFile)
	if err != nil {
		t.Fatalf("reading the new certificate: %v", err)
	}
	if string(newCert) == string(staleCert) {
		t.Fatal("the split pair has to be repaired with a new certificate")
	}
	// The key on disk should not have been replaced: LoadOrCreateKey does not
	// touch an existing file, and the pair is repaired from the certificate
	// side.
	keyOnDisk, err := os.ReadFile(d.KeyFile)
	if err != nil {
		t.Fatalf("reading the key: %v", err)
	}
	stillSameKey, err := parseECKey(d.KeyFile, keyOnDisk)
	if err != nil {
		t.Fatalf("parsing the key: %v", err)
	}
	if !stillSameKey.PublicKey.Equal(&mismatchedKey.PublicKey) {
		t.Fatal("the key on disk has to stay the very same one — only the certificate is repaired")
	}
	if _, err := os.Stat(d.JoinTokenFile); !os.IsNotExist(err) {
		t.Fatal("the token has to be deleted after a successful re-join")
	}
	// And the main thing — the resulting pair has to actually match: that is
	// the fact only os.Stat used to check, and which would previously have
	// accepted this very combination of files as a valid identity.
	if _, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile); err != nil {
		t.Fatalf("the resulting pair does not match: %v", err)
	}
}

// The same split case (the certificate is valid, there is no key), but with no
// token there is nothing to join again with — Ensure has to refuse clearly,
// and the message has to name the file that is actually missing (the key)
// rather than reason about the certificate, which is in fact in place. Ensure
// also has no business creating an orphan key when the pair cannot be restored
// anyway.
func TestEnsureFailsWhenValidCertificateHasNoKeyAndNoToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	writeFile(t, d.CertFile, ca.leaf(t, time.Now().Add(time.Hour)))
	// Neither a key nor a token.

	err := Ensure(context.Background(), d)
	if err == nil {
		t.Fatal("a valid certificate with no key and no token has to fail Ensure")
	}
	if !strings.Contains(err.Error(), d.KeyFile) {
		t.Fatalf("the error has to name the missing key file, got: %v", err)
	}
	if _, statErr := os.Stat(d.KeyFile); !os.IsNotExist(statErr) {
		t.Fatal("Ensure has no business creating a key when there is nothing to join again with")
	}
}

func TestEnsureFailsWithoutCertificateAndWithoutToken(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)

	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "join-token") {
		t.Fatalf("no certificate and no token — there has to be a clear refusal, got: %v", err)
	}
}

func TestEnsureReportsExpiredDistinctlyFromAbsent(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	writeFile(t, d.CertFile, ca.leaf(t, time.Now().Add(-time.Minute)))

	err := Ensure(context.Background(), d)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired certificate with no token has to be called expired, got: %v", err)
	}
}

// An unreadable certificate is not the same thing as an absent one: valid
// credentials may be sitting under it. Ensure has to refuse by itself and NOT
// touch join, otherwise it risks burning the one single-use token on a join
// that was not needed. A directory in place of the certificate file produces a
// read error that is not os.ErrNotExist.
func TestEnsureFailsClosedWhenCertificateUnreadable(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	d := ensureDeps(t, dir, "control_plane")
	writeFile(t, d.CAFile, ca.pem)
	if err := os.Mkdir(d.CertFile, 0o755); err != nil {
		t.Fatalf("directory in place of the certificate file: %v", err)
	}
	writeFile(t, d.JoinTokenFile, []byte("do-not-touch"))

	err := Ensure(context.Background(), d)
	if err == nil {
		t.Fatal("an unreadable certificate has to fail Ensure, not quietly start a join")
	}
	if strings.Contains(err.Error(), "join-token") {
		t.Fatalf("the error has no business sounding like a missing token, got: %v", err)
	}
	if _, statErr := os.Stat(d.JoinTokenFile); statErr != nil {
		t.Fatal("the token has no business being touched while Join was never called")
	}
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}
