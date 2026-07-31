package pkiclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Deps is everything needed to obtain and maintain a certificate, without a
// single field that is specific to a kind of participant.
//
// This used to hold the executor's whole *config.Config, and that was the one
// reason the package could not be used from anywhere else. Explicit fields
// instead: the caller decides which of its own config to take them from, and
// the module does not have to know the shape of any of them.
type Deps struct {
	// Mode is the gate. Join is skipped entirely unless this is
	// "control_plane". This is exactly what protects a running daemon from a
	// rollout of new code: the binary arrives, and the certificate is left
	// alone until someone flips the switch deliberately.
	Mode string

	PKIURL        string
	JoinTokenFile string
	CAFile        string
	CertFile      string
	KeyFile       string

	Identity Identity
	// Extra is the payload that only makes sense for kind node: region,
	// capacity, addresses, agent_version. An empty map for service and client.
	// A map[string]any rather than a struct, because the module has no business
	// knowing what an executor's capacity is.
	Extra map[string]any

	Log *slog.Logger
	Now func() time.Time
}

// Ensure brings a participant to the state where it has a valid certificate,
// or refuses to start with a clear reason.
//
// It is called BEFORE the caller's own file validation: that validation
// usually fails hard on a missing certificate, and a missing certificate is
// precisely the case join exists for.
func Ensure(ctx context.Context, d Deps) error {
	// Mode is the gate (§3.2 of the contract). In webhook mode join is skipped
	// entirely, and that is what protects a running participant from a rollout
	// of this code.
	if d.Mode != "control_plane" {
		d.Log.Info("join skipped", "mode", d.Mode)
		return nil
	}

	roots, caPEM, err := LoadRoots(d.CAFile)
	if err != nil {
		return fmt.Errorf("%w — a pinned ca.pem is mandatory both for join and for verifying our own certificate", err)
	}

	// A shared Join call for both places below where it may be needed: the
	// ordinary missing/unusable certificate, and a valid certificate with no
	// key. caPEM and roots are captured from the closure so that Params is not
	// assembled twice and two copies cannot drift apart.
	joinNow := func(token string) error {
		return Join(ctx, Params{
			URL: d.PKIURL, Token: token,
			TokenPath: d.JoinTokenFile,
			Identity:  d.Identity,
			CertPath:  d.CertFile, KeyPath: d.KeyFile,
			CAPEM: caPEM, Roots: roots,
			Extra: d.Extra,
		}, d.Log)
	}

	state, cert, inspectErr := Inspect(d.CertFile, roots, d.Identity.Kind, d.Now())
	token, tokenErr := readToken(d.JoinTokenFile)

	if state == CertValid {
		// Valid on its own does not mean usable: a TLS handshake stands on a
		// pair, not on one file. os.Stat here used to check only that the key
		// file exists — not that it forms a pair with this particular
		// certificate. A split pair (valid certificate + foreign or missing
		// key) passed that check indistinguishably from an intact one, and the
		// caller failed at tls.LoadX509KeyPair only after its own file
		// validation had let the pair through as well — without a single
		// chance at a join, even with a fresh token sitting right there (C2 of
		// the final review). tls.LoadX509KeyPair is not an optimisation on top
		// of os.Stat, it is the only way to learn that the private key matches
		// the public key in the certificate.
		if _, pairErr := tls.LoadX509KeyPair(d.CertFile, d.KeyFile); pairErr != nil {
			if tokenErr != nil {
				return fmt.Errorf("certificate %s is valid but does not form a pair with key %s (%v), and the join-token could not be read (%v): "+
					"the pair is split and there is nothing to join with again", d.CertFile, d.KeyFile, pairErr, tokenErr)
			}
			// LoadOrCreateKey inside Join creates a key only when there is
			// none on disk, and never touches an existing one — so calling
			// Join here cannot wipe a key this certificate would depend on:
			// since the pair does not match, there was nothing to depend on
			// (either there is no key at all, or it is no longer the one
			// signed into the certificate). Join will issue a certificate
			// consistent with the key that actually lies on disk (or create a
			// new one if there is none) and overwrite the orphaned
			// certificate.
			d.Log.Warn("certificate is valid but does not form a pair with the key — joining again",
				"cert", d.CertFile, "key", d.KeyFile, "error", pairErr)
			return joinNow(token)
		}
		if tokenErr == nil {
			d.Log.Warn("an unused join token lies next to a valid certificate; it was not deleted",
				"path", d.JoinTokenFile)
		}
		d.Log.Info("certificate in place, no join needed", "not_after", cert.NotAfter)
		return nil
	}

	// The file is there but could not be read: valid credentials could have
	// been sitting under it. We refuse by ourselves instead of mistaking this
	// for CertAbsent and burning a single-use token on a join that was not
	// needed at all.
	if state == CertUnreadable {
		return fmt.Errorf("certificate %s is on disk but could not be read: %w — "+
			"join is not started, so a single-use token is not burned blindly", d.CertFile, inspectErr)
	}

	if tokenErr != nil {
		return fmt.Errorf("certificate is in state %q and the join-token could not be read (%v): "+
			"there is nothing to join with", state, tokenErr)
	}

	d.Log.Info("joining the Control Plane", "kind", string(d.Identity.Kind), "cert_state", string(state), "url", d.PKIURL)
	return joinNow(token)
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("join_token_file is not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return token, nil
}
