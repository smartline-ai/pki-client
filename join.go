package pkiclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"time"
)

// ErrJoinRejected is a refusal that retries will not turn into a success: a
// wrong token, a malformed CSR, a foreign CN.
var ErrJoinRejected = errors.New("pkiclient: Control Plane rejected the join")

const (
	joinTimeout     = 10 * time.Minute
	joinBackoffCap  = 30 * time.Second
	joinHTTPTimeout = 30 * time.Second
)

// Params is all the input for a single join.
//
// This used to hold NodeID/Region/AgentVersion/Addresses/Capacity — fields
// that only make sense for kind node. Now what goes into the CSR (CN, IP) is
// carried by Identity, and everything else that only makes sense for one
// specific kind lives in Extra: it is expanded into the same top-level body
// keys that region/addresses/capacity/agent_version used before the
// generalisation.
type Params struct {
	URL       string
	Token     string
	TokenPath string
	Identity  Identity
	CertPath  string
	KeyPath   string
	CAPEM     []byte
	Roots     *x509.CertPool
	// Extra is the payload that only makes sense for kind node: region,
	// capacity, addresses, agent_version. An empty map for service and client.
	Extra map[string]any
	// Backoff is the initial pause between attempts. Zero means one second; in
	// tests it is set to milliseconds so nothing actually waits.
	Backoff time.Duration
}

// joinRequest is the body of POST /v1/principals/join.
type joinRequest struct {
	JoinToken string
	Kind      string
	CN        string
	CSRPEM    string
	// NodeID is kept for kind node: the old /v1/nodes/join endpoint reads
	// exactly this, and it stays alive for the whole switchover period (plan
	// 02, task 5; control-plane/internal/api/joinrouter.go). Not filled in for
	// service/client.
	NodeID string
	Extra  map[string]any
}

// MarshalJSON assembles join_token/kind/cn/csr_pem[/node_id] and expands Extra
// into the same top-level keys. That keeps the join body for kind node
// byte-for-byte what it was before the generalisation — node_id,
// addresses.private_ip, capacity, region, agent_version — while service/client
// simply have no extra fields, because their Extra is empty.
func (r joinRequest) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, len(r.Extra)+5)
	for k, v := range r.Extra {
		m[k] = v
	}
	m["join_token"] = r.JoinToken
	m["kind"] = r.Kind
	m["cn"] = r.CN
	m["csr_pem"] = r.CSRPEM
	if r.NodeID != "" {
		m["node_id"] = r.NodeID
	}
	return json.Marshal(m)
}

type joinResponse struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
}

// Join performs the whole join: the key is already on disk (the caller put it
// there), the CSR leaves from here and the certificate comes back here.
func Join(ctx context.Context, p Params, log *slog.Logger) error {
	key, err := LoadOrCreateKey(p.KeyPath)
	if err != nil {
		return err
	}
	csrPEM, err := buildCSR(key, p.Identity)
	if err != nil {
		return err
	}

	hc := &http.Client{
		Timeout: joinHTTPTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    p.Roots,
			MinVersion: tls.VersionTLS13,
		}},
	}

	// node_id is filled in only for kind node: the old endpoint reads exactly
	// that, and for this kind the CN is the node_id (design §11).
	var nodeID string
	if p.Identity.Kind == KindNode {
		nodeID = p.Identity.CN
	}
	body, err := json.Marshal(joinRequest{
		JoinToken: p.Token, Kind: string(p.Identity.Kind), CN: p.Identity.CN,
		CSRPEM: string(csrPEM), NodeID: nodeID, Extra: p.Extra,
	})
	if err != nil {
		return fmt.Errorf("pkiclient: assembling join body: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, joinTimeout)
	defer cancel()

	backoff := p.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	for attempt := 0; ; attempt++ {
		resp, err := postJoin(ctx, hc, p.URL+"/v1/principals/join", body)
		if err == nil {
			return installCert(p, key, resp, log)
		}
		if errors.Is(err, ErrJoinRejected) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("pkiclient: join did not succeed within %s: %w", joinTimeout, err)
		}
		wait := time.Duration(math.Min(
			float64(backoff)*math.Pow(2, float64(attempt)),
			float64(joinBackoffCap)))
		log.Warn("join failed, retrying", "attempt", attempt+1, "wait", wait, "error", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("pkiclient: join did not succeed within %s: %w", joinTimeout, err)
		case <-time.After(wait):
		}
	}
}

func postJoin(ctx context.Context, hc *http.Client, url string, body []byte) (*joinResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pkiclient: join request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: calling %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// The body is not quoted: there is nothing in it that is not in the
		// code, and the token has no business being in the log.
		return nil, fmt.Errorf("%w: HTTP %d", ErrJoinRejected, resp.StatusCode)
	default:
		return nil, fmt.Errorf("pkiclient: Control Plane answered HTTP %d", resp.StatusCode)
	}

	var out joinResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("pkiclient: join response does not parse: %w", err)
	}
	if out.CertPEM == "" {
		return nil, fmt.Errorf("pkiclient: join response without cert_pem")
	}
	return &out, nil
}

// installCert verifies the issued certificate before it lands on disk.
func installCert(p Params, key *ecdsa.PrivateKey, resp *joinResponse, log *slog.Logger) error {
	cert, err := verifyIssuedCert(resp.CertPEM, key, p.Roots, p.Identity.Kind)
	if err != nil {
		return fmt.Errorf("pkiclient: %w", err)
	}

	if err := WriteFileAtomic(p.CertPath, []byte(resp.CertPEM), 0o644); err != nil {
		return err
	}
	// The token is deleted only now: up to this point a retry still makes
	// sense.
	if p.TokenPath != "" {
		if err := os.Remove(p.TokenPath); err != nil && !os.IsNotExist(err) {
			log.Warn("token file was not deleted", "path", p.TokenPath, "error", err)
		}
	}
	log.Info("participant joined", "kind", string(p.Identity.Kind), "cn", p.Identity.CN, "not_after", cert.NotAfter)
	return nil
}

// verifyIssuedCert parses and verifies the certificate that came back from the
// Control Plane, before it touches the disk. Shared by join (installCert) and
// renew (renewOnce): before one of the earlier reviews the two copies had
// drifted apart — renew had no public-key check at all, which let a
// certificate issued for the wrong key land on disk and leave the node with a
// split pair.
//
// There are two checks and both are mandatory: the chain to the pinned CA —
// against a substituted Control Plane, and the public-key match — against a
// certificate we have no private key for.
//
// kind selects the expected EKU via expectedKeyUsage (certstate.go): the
// Control Plane issues node and client leaves with clientAuth alone (never
// serverAuth), and a participant that requires the wrong one falls over on its
// own check of the certificate it was just sent, without ever questioning that
// certificate on the merits.
//
// That failure gets its own error, ErrWrongKeyUsage, rather than the chain
// wording below (checkChain, certstate.go). It is the one refusal here that
// says nothing about the certificate and everything about the two sides having
// been released out of step, and the cost of folding it into "does not chain to
// the pinned CA" was a fleet-wide outage diagnosed as a CA problem.
func verifyIssuedCert(certPEM string, key *ecdsa.PrivateKey, roots *x509.CertPool, kind Kind) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cert_pem does not parse")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the issued certificate: %w", err)
	}
	// The zero time means "now" to crypto/x509, which is what a freshly issued
	// certificate has to be judged against.
	if err := checkChain(cert, roots, kind, time.Time{}); err != nil {
		if errors.Is(err, ErrWrongKeyUsage) {
			return nil, fmt.Errorf("the issued certificate is unusable: %w", err)
		}
		return nil, fmt.Errorf("the issued certificate does not chain to the pinned CA: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("the certificate was issued for a foreign key")
	}
	return cert, nil
}

// buildCSR assembles the CSR for a specific kind of participant. CN is always
// id.CN; IPAddresses is set only when id.IP != nil. For client, IP is always
// nil and the CSR is left with no SAN IP at all — which is what
// control-plane/internal/pki.ValidateCSR requires for a client leaf (empty
// IPAddresses, otherwise a refusal).
func buildCSR(key *ecdsa.PrivateKey, id Identity) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: id.CN},
		DNSNames:           []string{id.CN},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	if id.IP != nil {
		tmpl.IPAddresses = []net.IP{id.IP}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("pkiclient: creating CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}
