package pkiclient

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
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
	CertValid       CertState = "valid"
)

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

// expectedKeyUsage is the EKU the leaf's own holder is entitled to require
// when verifying its own certificate. It mirrors the choice made in
// control-plane/internal/pki.SignLeaf: node and service get a leaf with both
// EKUs (serverAuth+clientAuth) and are checked here against serverAuth — which
// is enough, Verify accepts any match from the list — while client gets a leaf
// with clientAuth only and has to be checked against that.
// This used to be one and the same ServerAuth constant for every kind, and a
// client leaf, which has no serverAuth at all, failed verification on its own
// side without ever reaching the Control Plane.
func expectedKeyUsage(kind Kind) x509.ExtKeyUsage {
	if kind == KindClient {
		return x509.ExtKeyUsageClientAuth
	}
	return x509.ExtKeyUsageServerAuth
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
// kind selects the expected EKU (expectedKeyUsage) — a client leaf carries
// clientAuth only and would not pass the serverAuth check this function
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
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{expectedKeyUsage(kind)},
	}); err != nil {
		return CertForeignCA, cert, nil
	}
	return CertValid, cert, nil
}
