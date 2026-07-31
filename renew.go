package pkiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// CertSource is what stands between the file on disk and a live TLS listener.
//
// Without it a renewal that rewrote the file changes nothing for a process
// started months ago: it keeps presenting the old certificate straight through
// the expiry date, and it looks like the CP suddenly being unable to reach an
// obviously working participant.
type CertSource struct {
	cur atomic.Pointer[tls.Certificate]
}

func (s *CertSource) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := s.cur.Load()
	if c == nil {
		return nil, fmt.Errorf("pkiclient: certificate not loaded yet")
	}
	return c, nil
}

func (s *CertSource) Set(c *tls.Certificate) { s.cur.Store(c) }

// Load reads the pair from disk and swaps the pointer. Leaf is filled in
// explicitly: tls.LoadX509KeyPair does not fill it, and the renewal loop reads
// the lifetime off it.
func (s *CertSource) Load(certPath, keyPath string) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("pkiclient: loading the pair %s: %w", certPath, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("pkiclient: parsing the leaf %s: %w", certPath, err)
	}
	cert.Leaf = leaf
	s.cur.Store(&cert)
	return nil
}

// NeedsRenewal is a third of the certificate's own lifetime before NotAfter.
// The lifetime is taken from the leaf itself rather than from the config: the
// TTL is chosen by the CP, and the participant learns it only from the issued
// certificate.
func NeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	if cert == nil {
		return true
	}
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return now.After(cert.NotAfter.Add(-lifetime / 3))
}

// RunRenewal checks the lifetime once every `every` and renews the
// certificate.
//
// An hour was chosen not for precision at the threshold, but so that a
// participant that spent time powered off notices an approaching expiry soon
// after it comes back up rather than a day later.
func RunRenewal(ctx context.Context, d Deps, src *CertSource, every time.Duration) {
	// The same gate as in Ensure (§3.2 of the contract, ensure.go). Without it
	// this goroutine would start unconditionally on every participant: on
	// dev-1 that goes unnoticed today only because its certificate lives 3650
	// days and NeedsRenewal never fires — but a participant in webhook or none
	// mode may have no pki_url at all, and any other one with a shorter
	// certificate would send CSRs to a place where join is forbidden to it
	// (final review, I2).
	if d.Mode != "control_plane" {
		d.Log.Info("certificate renewal skipped", "mode", d.Mode)
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur, err := src.Get(nil)
			if err != nil {
				continue
			}
			if !NeedsRenewal(cur.Leaf, now) {
				continue
			}
			if err := renewOnce(ctx, d, src); err != nil {
				// Not fatal: the current certificate is still alive for a
				// whole third of its lifetime, and dying over one failure
				// would mean taking down a participant with running projects
				// because the CP was unreachable for a minute.
				d.Log.Error("certificate renewal failed", "error", err)
			}
		}
	}
}

func renewOnce(ctx context.Context, d Deps, src *CertSource) error {
	roots, _, err := LoadRoots(d.CAFile)
	if err != nil {
		return err
	}
	// The key is reused: key rotation is not made crash-safe across two
	// separate paths in the config — a crash between renaming the key and
	// renaming the certificate would leave a mismatched pair and a daemon that
	// does not start (§6.2 of the design).
	key, err := LoadOrCreateKey(d.KeyFile)
	if err != nil {
		return err
	}
	csrPEM, err := buildCSR(key, d.Identity)
	if err != nil {
		return err
	}

	cur, err := src.Get(nil)
	if err != nil {
		return err
	}
	hc := &http.Client{
		Timeout: joinHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{*cur},
		}},
	}

	body, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return err
	}
	// The generalised endpoint (control-plane/internal/api/joinrouter.go):
	// kind/cn in the path instead of node_id is the only route that serves all
	// three kinds without an alias, so it is used here rather than the old
	// /v1/nodes/{node_id}/renew.
	url := d.PKIURL + "/v1/principals/" + string(d.Identity.Kind) + "/" + d.Identity.CN + "/renew"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("pkiclient: calling %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pkiclient: renewal rejected, HTTP %d", resp.StatusCode)
	}

	var out joinResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("pkiclient: renewal response does not parse: %w", err)
	}
	// The same check as in join (verifyIssuedCert, join.go), including the
	// public-key match — only the chain used to be verified here, and a
	// certificate for a foreign key would have landed on disk, leaving the
	// node with a split pair. Both checks happen before the write: otherwise
	// the window between WriteFileAtomic and src.Load could diverge from the
	// disk on a certificate there is no key for at all.
	cert, err := verifyIssuedCert(out.CertPEM, key, roots, d.Identity.Kind)
	if err != nil {
		return fmt.Errorf("pkiclient: the renewed certificate failed verification: %w", err)
	}

	if err := WriteFileAtomic(d.CertFile, []byte(out.CertPEM), 0o644); err != nil {
		return err
	}
	// The file on disk and the pointer in memory have to change in this order:
	// otherwise a crash between them leaves the process with a certificate
	// that is not on disk, and the next start rolls back.
	if err := src.Load(d.CertFile, d.KeyFile); err != nil {
		return err
	}
	d.Log.Info("certificate renewed", "not_after", cert.NotAfter)
	return nil
}
