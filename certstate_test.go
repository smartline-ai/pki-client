package pkiclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func makeCA(t *testing.T) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) leaf(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "n-01j9qk3m7x2v5tpb8w4h6n0zya"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca testCA) leafFor(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "n-01j9qk3m7x2v5tpb8w4h6n0zya"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("leaf for the given key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// clientLeafFor issues a leaf with clientAuth as the only ExtKeyUsage — the
// shape the Control Plane actually issues kind client in
// (control-plane/internal/pki.SignLeaf), unlike leaf()/leafFor() above, which
// carry serverAuth.
func (ca testCA) clientLeafFor(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "ops-laptop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("client leaf: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func (ca testCA) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(ca.pem) {
		t.Fatal("the CA was not added to the pool")
	}
	return p
}

func TestInspectClassifies(t *testing.T) {
	ours := makeCA(t)
	foreign := makeCA(t)
	dir := t.TempDir()
	now := time.Now()

	write := func(name string, body []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return p
	}

	cases := []struct {
		name string
		path string
		want CertState
	}{
		{"no file", filepath.Join(dir, "missing.pem"), CertAbsent},
		{"not PEM", write("garbage.pem", []byte("not a certificate")), CertUnparseable},
		{"expired", write("old.pem", ours.leaf(t, now.Add(-time.Minute))), CertExpired},
		{"foreign CA", write("foreign.pem", foreign.leaf(t, now.Add(time.Hour))), CertForeignCA},
		{"valid", write("good.pem", ours.leaf(t, now.Add(time.Hour))), CertValid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := Inspect(c.path, ours.pool(t), KindNode, now)
			if got != c.want {
				t.Fatalf("Inspect = %q, expected %q", got, c.want)
			}
		})
	}
}

// A present but unreadable certificate has to differ from an absent one: valid
// credentials may be sitting under it, and keeping those two cases apart is
// the whole point of Inspect. A directory in place of the certificate file is
// the simplest reproducible way to get a read error that is not
// os.ErrNotExist.
func TestInspectDistinguishesUnreadableFromAbsent(t *testing.T) {
	ours := makeCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.pem")
	if err := os.Mkdir(certPath, 0o755); err != nil {
		t.Fatalf("directory in place of the certificate file: %v", err)
	}

	state, cert, err := Inspect(certPath, ours.pool(t), KindNode, time.Now())
	if state != CertUnreadable {
		t.Fatalf("Inspect = %q, expected %q", state, CertUnreadable)
	}
	if cert != nil {
		t.Fatal("an unreadable certificate has no business returning a parsed *x509.Certificate")
	}
	if err == nil {
		t.Fatal("an unreadable certificate has to return the original read error")
	}
}

// Key reuse is what makes the retry path correct: the second join attempt has
// to carry the same public key, otherwise the CP rejects it.
func TestLoadOrCreateKeyReusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-key.pem")

	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the key file was not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode is %v, expected 0600", info.Mode().Perm())
	}

	second, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !first.PublicKey.Equal(&second.PublicKey) {
		t.Fatal("a repeat call has to return the same key, not generate a new one")
	}
}

// Two concurrent first callers (cold start, a race) have to converge on one
// key — the one that actually lies on disk. Without the atomic "exactly one
// wins" publication every loser generates its own key and, depending on whose
// write landed on disk last, may hand the caller a key different from the
// stored one — which is exactly what key reuse has to prevent (see
// TestLoadOrCreateKeyReusesExisting).
func TestLoadOrCreateKeyConcurrentCallersConverge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-key.pem")
	const n = 32

	var start, ready, done sync.WaitGroup
	start.Add(1)
	ready.Add(n)
	done.Add(n)

	keys := make([]*ecdsa.PrivateKey, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			start.Wait()
			keys[i], errs[i] = LoadOrCreateKey(path)
		}(i)
	}
	ready.Wait() // every goroutine has reached the start line before we open it
	start.Done()
	done.Wait() // and all of them must finish their call before keys/errs are read below

	// t.Fatalf from a goroutine is against the rules of testing.T, so every
	// LoadOrCreateKey call writes its result into errs/keys, and we fail here,
	// in the test body, after all the goroutines have finished.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the resulting key file: %v", err)
	}
	block, _ := pem.Decode(onDisk)
	if block == nil {
		t.Fatal("the resulting key file is not PEM")
	}
	diskKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parsing the resulting key on disk: %v", err)
	}

	for i, k := range keys {
		if !k.PublicKey.Equal(&diskKey.PublicKey) {
			t.Fatalf("call %d returned a key different from the one that actually lies on disk", i)
		}
	}
}
