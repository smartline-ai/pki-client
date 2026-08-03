package pkiclient

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// CertState is what lies on disk, seen through the question "do we join or
// not". A string rather than an int: it ends up in the log, and "foreign_ca"
// reads better than "3".
type CertState string

const (
	CertAbsent      CertState = "absent"
	CertUnreadable  CertState = "unreadable"
	CertUnparseable CertState = "unparseable"
	CertExpired     CertState = "expired"
	CertForeignCA   CertState = "foreign_ca"
	// CertWrongEKU is a certificate that is in date and chains honestly to our
	// own pinned CA, and is still unusable: it does not carry the extended key
	// usage this kind of participant is verified against. It is split out of
	// CertForeignCA on the same grounds CertExpired is — "foreign_ca" is a
	// question about who signed this, "wrong_eku" is a question about what the
	// two sides believe the certificate is for, and the answers point at
	// opposite ends of the fleet. wrong_eku on a certificate the CP itself
	// issued means our own CA and this module disagree, which is a code or
	// version skew, not an attack and not a misconfigured root.
	CertWrongEKU CertState = "wrong_eku"
	CertValid    CertState = "valid"
)

// ErrWrongKeyUsage is the join/renew-side twin of CertWrongEKU: the certificate
// the Control Plane just issued chains to the pinned CA and is in date, and
// carries an EKU this kind is not verified against.
//
// It is worth a sentinel of its own because it is the one failure here that is
// nobody's fault out on the fleet — not a stolen key, not a substituted CP, not
// a stale root — and the only one an operator fixes by shipping a version
// rather than by touching the machine.
var ErrWrongKeyUsage = errors.New("wrong extended key usage")

// LoadRoots reads the pinned CA. It is always mandatory: without it a node can
// neither verify the Control Plane during join nor tell whether the
// certificate on its disk is its own.
func LoadRoots(caPath string) (*x509.CertPool, []byte, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, fmt.Errorf("pkiclient: reading CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("pkiclient: %s contains no certificates", caPath)
	}
	return pool, caPEM, nil
}

// expectedKeyUsage is the EKU the holder of a leaf requires when verifying its
// own certificate. It has to mirror, kind for kind, what
// control-plane/internal/pki.SignLeaf actually stamps into the leaf: the two
// are a single contract written down in two repositories that release
// separately, and nothing enforces it but TestExpectedKeyUsageMatchesTheIssuedLeaf.
//
// A switch over all three kinds rather than a default: the interesting fact
// about this function is which side each kind falls on, and a two-branch if
// states that for one kind and leaves the other two to be inferred.
//
//   - KindNode — clientAuth. A node is a TLS client and nothing else as of
//     stage 2. Nothing dials a node any more: it dials the Control Plane and
//     long-polls GET /v1/agent/work, so the CP stopped issuing it serverAuth, a
//     DNS name or a SAN IP at all. Reading this line the other way round — "a
//     node is a server, surely" — is the mistake that cost a fleet its joins;
//     node sat next to service here while the CA had already moved it next to
//     client.
//   - KindService — serverAuth. The edge proxy and the image builder are dialled
//     by address and genuinely serve TLS; they are the last kind whose address a
//     certificate still asserts. Their leaf carries serverAuth+clientAuth and
//     Verify accepts on any single match, so serverAuth is the half worth
//     asking for: it is the half that tells a service leaf from every other.
//   - KindClient — clientAuth. Always was. A client has no address anyone would
//     dial, and must not hold a certificate it could stand a server up with.
func expectedKeyUsage(kind Kind) x509.ExtKeyUsage {
	switch kind {
	case KindNode, KindClient:
		return x509.ExtKeyUsageClientAuth
	case KindService:
		return x509.ExtKeyUsageServerAuth
	default:
		// An unset or misspelled Kind is a caller's bug, and no answer here
		// makes it work. serverAuth is the answer that fails loudest: only a
		// service leaf carries it, so everything else lands in the wrong-EKU
		// branch below and names the kind out loud, instead of being waved
		// through into a handshake that fails later somewhere with no context.
		return x509.ExtKeyUsageServerAuth
	}
}

// checkChain runs the verification both the join path and the on-disk path
// need, and separates its two ways of failing.
//
// crypto/x509 does not separate them: Verify reports "certificate specifies an
// incompatible key usage" through the same return as an unknown authority, so a
// caller that knows only "Verify said no" can do no better than blame whatever
// it asked about — and blame the CA it pinned for a disagreement about EKUs.
// That is precisely what happened: every node in the fleet died naming the CA,
// and the CA was never in question.
//
// The strict verification runs first, so the path that succeeds pays for
// nothing extra. Only after it fails is the second, EKU-blind pass made, and
// only to answer whether the chain itself was ever in doubt.
func checkChain(cert *x509.Certificate, roots *x509.CertPool, kind Kind, now time.Time) error {
	want := expectedKeyUsage(kind)
	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{want},
	}
	if _, err := cert.Verify(opts); err != nil {
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		if _, anyErr := cert.Verify(opts); anyErr == nil {
			return fmt.Errorf("%w: kind %s is verified against %s, this certificate carries %s",
				ErrWrongKeyUsage, kind, ekuName(want), ekuNames(cert.ExtKeyUsage))
		}
		return err
	}
	return nil
}

// ekuName and ekuNames exist for the message above. x509.ExtKeyUsage is an int,
// and a refusal that says "expected 1, got 2" costs the reader the trip to the
// crypto/x509 source that this whole classification is meant to save them.
func ekuName(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	default:
		return fmt.Sprintf("EKU %d", eku)
	}
}

func ekuNames(ekus []x509.ExtKeyUsage) string {
	if len(ekus) == 0 {
		return "none"
	}
	names := make([]string, len(ekus))
	for i, eku := range ekus {
		names[i] = ekuName(eku)
	}
	return strings.Join(names, "+")
}

// Inspect classifies the certificate. The order of the checks matters: an
// expired certificate from our own CA and a valid one from a foreign CA are
// different stories, and they have to look different in the log, otherwise
// diagnosis bottoms out at "TLS does not work".
//
// CertAbsent and CertUnreadable are different stories too, even though both
// mean "no certificate we can present". CertAbsent means there is no file on
// disk and a join is in order. CertUnreadable means the file is there but
// could not be read (permissions, it is a directory, the disk fell off); valid
// credentials could have been sitting there, and the caller has to refuse by
// itself rather than quietly decide that a join is safe. The third return
// value is non-nil only for CertUnreadable and carries the original read
// error.
//
// kind selects the expected EKU (expectedKeyUsage) — a node or client leaf
// carries clientAuth only and would not pass the serverAuth check this function
// required unconditionally before that parameter existed.
func Inspect(certPath string, roots *x509.CertPool, kind Kind, now time.Time) (CertState, *x509.Certificate, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CertAbsent, nil, nil
		}
		return CertUnreadable, nil, fmt.Errorf("pkiclient: reading certificate %s: %w", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertUnparseable, nil, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertUnparseable, nil, nil
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return CertExpired, cert, nil
	}
	if err := checkChain(cert, roots, kind, now); err != nil {
		if errors.Is(err, ErrWrongKeyUsage) {
			return CertWrongEKU, cert, nil
		}
		return CertForeignCA, cert, nil
	}
	return CertValid, cert, nil
}
