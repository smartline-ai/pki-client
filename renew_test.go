package pkiclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The threshold is measured against the leaf's actual lifetime, not against
// the config: a participant does not know the TTL the CP issued it with and
// has to derive it from NotBefore/NotAfter.
func TestNeedsRenewalUsesCertificateOwnLifetime(t *testing.T) {
	issued := time.Now()
	cert := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(90 * 24 * time.Hour),
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"right after issuance", issued, false},
		{"on day 59", issued.Add(59 * 24 * time.Hour), false},
		{"on day 61", issued.Add(61 * 24 * time.Hour), true},
		{"after expiry", issued.Add(91 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := NeedsRenewal(cert, c.at); got != c.want {
			t.Errorf("%s: NeedsRenewal = %v, expected %v", c.name, got, c.want)
		}
	}
	if !NeedsRenewal(nil, issued) {
		t.Error("a missing certificate has to require renewal")
	}
}

// The point of the source: a server started months ago has to begin
// presenting the new certificate without a restart.
func TestCertSourceSwapsWithoutRestart(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	first, err := src.Get(&tls.ClientHelloInfo{})
	if err != nil || first == nil {
		t.Fatalf("Get: cert=%v err=%v", first, err)
	}

	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(48*time.Hour)))
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	second, _ := src.Get(&tls.ClientHelloInfo{})
	if second == first {
		t.Fatal("after a reload the source has to hand out the new certificate")
	}
	if !second.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("the new certificate has to be fresher than the old one")
	}
}

// Complements TestNeedsRenewalUsesCertificateOwnLifetime: that test is built
// entirely on a 90-day certificate, so an implementation with hard-coded
// 90/30-day constants would pass it unnoticed. Here the leaf's lifetime is
// different (30 days) and the threshold has to move proportionally with it —
// otherwise what is being checked is not "a third of its own lifetime" but a
// coincidence with the test's special case.
func TestNeedsRenewalScalesWithCertificatesOwnLifetime(t *testing.T) {
	issued := time.Now()
	cert := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(30 * 24 * time.Hour),
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"on day 19 of 30 (before the third)", issued.Add(19 * 24 * time.Hour), false},
		{"on day 21 of 30 (after the third)", issued.Add(21 * 24 * time.Hour), true},
	}
	for _, c := range cases {
		if got := NeedsRenewal(cert, c.at); got != c.want {
			t.Errorf("%s: NeedsRenewal = %v, expected %v", c.name, got, c.want)
		}
	}
}

// RunRenewal has to react to context cancellation immediately rather than only
// on the next tick: otherwise stopping the daemon would block for `every`,
// deliberately longer here than any sensible test timeout.
func TestRunRenewalReturnsPromptlyOnContextCancellation(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(24*time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// Mode: control_plane — otherwise the test would be checking the I2
		// gate (see TestRunRenewalSkipsOutsideControlPlaneMode below), which
		// returns immediately even without a cancellation, rather than
		// cancellation inside the ticker.
		RunRenewal(ctx, Deps{
			Mode: "control_plane",
			Log:  discardLog(),
		}, &src, time.Hour)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunRenewal did not return within a second of the context being cancelled with every=1h")
	}
}

// I2 of the final review: RunRenewal has to stay silent outside control_plane
// exactly like Ensure/Join (ensure.go) — and not merely fail to fire "by
// accident" thanks to dev-1's certificate living 3650 days. The test sets
// every=1h and never cancels the context at all: had the gate been skipped,
// RunRenewal would block on the ticker and done would not close within the
// second it is given.
func TestRunRenewalSkipsOutsideControlPlaneMode(t *testing.T) {
	for _, mode := range []string{"webhook", "none", ""} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				RunRenewal(context.Background(), Deps{
					Mode: mode,
					Log:  discardLog(),
				}, &CertSource{}, time.Hour)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("RunRenewal(mode=%q) has to return immediately, without waiting for the ticker", mode)
			}
		})
	}
}

// The point of the "file first, then the pointer" order (§ the task's
// decisions) is checked by more than reading the code: after a successful
// renewal, disk and memory have to agree on one and the same certificate
// rather than on two different ones.
func TestRenewOnceKeepsDiskAndMemoryInAgreement(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, ca.pem)

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	writeFile(t, certPath, ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour)))

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}

	newNotAfter := time.Now().Add(48 * time.Hour)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaf := ca.leafFor(t, &key.PublicKey, newNotAfter)
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf)})
	}))
	defer srv.Close()

	d := Deps{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
		PKIURL:   srv.URL,
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Log: discardLog(),
	}

	if err := renewOnce(context.Background(), d, &src); err != nil {
		t.Fatalf("renewOnce: %v", err)
	}

	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	block, _ := pem.Decode(onDisk)
	diskCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the file: %v", err)
	}

	inMemory, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !diskCert.NotAfter.Equal(inMemory.Leaf.NotAfter) {
		t.Fatalf("disk (%s) and memory (%s) diverged after the renewal", diskCert.NotAfter, inMemory.Leaf.NotAfter)
	}
	if !inMemory.Leaf.NotAfter.After(time.Now().Add(47 * time.Hour)) {
		t.Fatalf("the in-memory certificate was not renewed: NotAfter=%s", inMemory.Leaf.NotAfter)
	}
}

// I3 of the final review: renewOnce checked only the chain to the pinned CA,
// not whether the issued certificate was made out to a key the participant
// actually has. A certificate that chains honestly and is nevertheless issued
// for the wrong key used to land on disk — and the next restart would find
// exactly the split pair C2 does not let you climb out of. The mirror of
// TestJoinRejectsCertificateOnForeignKey (join_test.go) for the renewal path.
func TestRenewOnceRejectsCertificateOnForeignKey(t *testing.T) {
	ca := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	keyPath := filepath.Join(dir, "node-key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, caPath, ca.pem)

	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	staleCert := ca.leafFor(t, &key.PublicKey, time.Now().Add(time.Hour))
	writeFile(t, certPath, staleCert)

	var src CertSource
	if err := src.Load(certPath, keyPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	foreignKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("foreign key: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The right CA (ca), but signed for a key the participant does not have.
		leaf := ca.leafFor(t, &foreignKey.PublicKey, time.Now().Add(48*time.Hour))
		json.NewEncoder(w).Encode(map[string]string{"cert_pem": string(leaf)})
	}))
	defer srv.Close()

	d := Deps{
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
		PKIURL:   srv.URL,
		Identity: Identity{
			Kind: KindNode,
			CN:   "n-01j9qk3m7x2v5tpb8w4h6n0zya",
			IP:   net.ParseIP("10.0.0.5"),
		},
		Log: discardLog(),
	}

	if err := renewOnce(context.Background(), d, &src); err == nil {
		t.Fatal("a certificate issued for a foreign key has to be rejected")
	}

	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading the file: %v", err)
	}
	if string(onDisk) != string(staleCert) {
		t.Fatal("a rejected certificate has no business landing on disk over the old one")
	}
	after, err := src.Get(nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after != before {
		t.Fatal("a rejected certificate has no business replacing the pointer in memory")
	}
}
