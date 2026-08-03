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

// leaf issues a node leaf on a key nobody has — every caller uses it to get a
// certificate whose private key is deliberately missing or stale. clientAuth
// alone, because that is what the Control Plane issues kind node since stage 2
// (control-plane/internal/pki.SignLeaf); a fixture that carried serverAuth
// would be testing a shape no CA hands out any more, and the tests standing on
// it would keep passing while a real node was turned away.
func (ca testCA) leaf(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return ca.leafWithEKU(t, &key.PublicKey, notAfter, x509.ExtKeyUsageClientAuth)
}

// leafWithEKU issues a leaf for the given public key carrying exactly the given
// extended key usages. The EKU set is the entire subject of the kind contract
// (expectedKeyUsage, certstate.go), so a test about that contract has to be
// able to state it outright instead of picking from a menu of pre-baked shapes.
func (ca testCA) leafWithEKU(t *testing.T, pub *ecdsa.PublicKey, notAfter time.Time, eku ...x509.ExtKeyUsage) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "n-01j9qk3m7x2v5tpb8w4h6n0zya"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("leaf with EKU %v: %v", eku, err)
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

// The EKU a leaf is verified against is one half of a contract pki-client
// shares with control-plane/internal/pki.SignLeaf, and until this test nothing
// in either repo checked that the two halves still agreed. Spelled out kind by
// kind:
//
//	node    — clientAuth only, since stage 2: nothing dials a node any more, it
//	          dials the Control Plane and long-polls.
//	service — serverAuth: the edge proxy and the image builder are dialled by
//	          address and genuinely serve TLS. The CP issues them
//	          serverAuth+clientAuth, and Verify accepts on any one match.
//	client  — clientAuth only, as it always was.
//
// While this was wrong for node, a fresh executor died after the Control Plane
// had already redeemed its single-use token: the leaf came back, the node
// refused its own certificate, nothing reached the disk, and every restart hit
// a token that was already spent. Three modules' test suites had nothing to
// say about it, because every node fixture in them carried serverAuth — a
// shape the CA had stopped issuing.
func TestExpectedKeyUsageMatchesTheIssuedLeaf(t *testing.T) {
	ours := makeCA(t)
	now := time.Now()

	cases := []struct {
		name  string
		kind  Kind
		eku   []x509.ExtKeyUsage
		valid bool
	}{
		{"node, as the CP issues it: clientAuth only", KindNode, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true},
		{"node, the pre-stage-2 shape: serverAuth only", KindNode, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		{"service, as the CP issues it: serverAuth+clientAuth", KindService, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, true},
		{"service without serverAuth: it is the one kind that still serves TLS", KindService, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false},
		{"client, as the CP issues it: clientAuth only", KindClient, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true},
		{"client without clientAuth", KindClient, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("key: %v", err)
			}
			leafPEM := ours.leafWithEKU(t, &key.PublicKey, now.Add(time.Hour), c.eku...)

			// verifyIssuedCert is the gate on both the join and the renew path
			// (join.go, renew.go): what it turns away never reaches disk at all.
			_, err = verifyIssuedCert(string(leafPEM), key, ours.pool(t), c.kind)
			switch {
			case c.valid && err != nil:
				t.Fatalf("verifyIssuedCert(kind=%s) turned away a leaf the CP issues for exactly that kind: %v", c.kind, err)
			case !c.valid && err == nil:
				t.Fatalf("verifyIssuedCert(kind=%s) accepted a leaf carrying %v", c.kind, c.eku)
			}

			// Inspect is the gate on every start after the first: a certificate
			// that was good enough to join must not read as unusable on the next
			// boot, or the participant joins again on a token that is gone.
			path := filepath.Join(t.TempDir(), "leaf.pem")
			if err := os.WriteFile(path, leafPEM, 0o644); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}
			state, _, _ := Inspect(path, ours.pool(t), c.kind, now)
			switch {
			case c.valid && state != CertValid:
				t.Fatalf("Inspect(kind=%s) = %q, expected %q", c.kind, state, CertValid)
			case !c.valid && state == CertValid:
				t.Fatalf("Inspect(kind=%s) called a leaf carrying %v valid", c.kind, c.eku)
			}
		})
	}
}

// "Our CA signed this and the EKU is wrong" and "this is not our CA at all"
// are the two failures Verify hands back through one and the same error, and
// they send an operator to opposite ends of the fleet: the first is a version
// skew between the CP and this module, fixed by a release; the second is a
// substituted or stale root, fixed on the machine. Inspect keeps expired and
// foreign_ca apart for exactly this reason, and wrong_eku earns the same
// treatment — while it did not have it, every executor in the fleet reported a
// CA problem it did not have.
//
// The last case is the one that makes the split worth checking: a certificate
// that fails both ways has to keep reporting the chain, because a leaf from an
// unknown CA is not made any more trustworthy by carrying the right EKU.
func TestInspectSeparatesWrongEKUFromForeignCA(t *testing.T) {
	ours := makeCA(t)
	foreign := makeCA(t)
	now := time.Now()

	cases := []struct {
		name string
		ca   testCA
		eku  x509.ExtKeyUsage
		want CertState
	}{
		{"ours, the EKU node is verified against", ours, x509.ExtKeyUsageClientAuth, CertValid},
		{"ours, the wrong EKU", ours, x509.ExtKeyUsageServerAuth, CertWrongEKU},
		{"foreign, the right EKU", foreign, x509.ExtKeyUsageClientAuth, CertForeignCA},
		{"foreign, the wrong EKU — the chain is the bigger question", foreign, x509.ExtKeyUsageServerAuth, CertForeignCA},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("key: %v", err)
			}
			path := filepath.Join(t.TempDir(), "node.pem")
			if err := os.WriteFile(path, c.ca.leafWithEKU(t, &key.PublicKey, now.Add(time.Hour), c.eku), 0o644); err != nil {
				t.Fatalf("writing %s: %v", path, err)
			}
			got, _, _ := Inspect(path, ours.pool(t), KindNode, now)
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
