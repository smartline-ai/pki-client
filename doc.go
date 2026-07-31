// Package pkiclient brings a fleet participant — a node, a service or a
// client — to the state where it has a working mTLS identity: it generates a
// key, joins the Control Plane with a single-use token and renews the
// certificate for as long as the process lives.
//
// Lifted out of executor-node/internal/bootstrap (plan 03, task 1). The
// package already implemented the whole certificate lifecycle — atomic writes,
// state inspection (CertValid/CertAbsent/CertExpiring/CertUnreadable), join by
// CSR, the check that the issued leaf matches the key it was signed for,
// renewal at a third of the remaining lifetime and hot swapping without a
// restart via CertSource — and was not up for a rewrite. It was node-specific
// in exactly two places: Deps carried the executor's whole *config.Config, and
// joinRequest hard-coded node_id/addresses/capacity. Both became explicit and
// kind-agnostic (Identity{Kind, CN, IP} and Extra map[string]any); the rest of
// the code did not change.
package pkiclient

import "net"

// Kind is the sort of participant the Control Plane issues credentials to. The
// three values match what the generalised POST /v1/principals/join endpoint
// now accepts (plan 02, task 2 of control-plane): kind determines what the
// bearer is entitled to ask for, together with the policy pinned to the join
// token on the CP side.
type Kind string

const (
	// KindNode is an executor. Server + client leaf, SAN is the single
	// RFC1918 address that comes into being on the node's own Volume.
	KindNode Kind = "node"
	// KindService is a daemon that listens but is not a node (a builder, for
	// example). SAN is the address pinned into the token at issue time.
	KindService Kind = "service"
	// KindClient is a party that only makes calls. A leaf with no SAN IP and
	// clientAuth only: a certificate you cannot present yourself as a server
	// with.
	KindClient Kind = "client"
)

// Identity is what goes into the CSR. CN is always present; IP is filled in
// only for kinds that have a network address (node, service) and stays nil for
// client — which is what makes buildCSR leave the SAN IP out of the template,
// as control-plane/internal/pki.ValidateCSR requires for a client leaf.
type Identity struct {
	Kind Kind
	CN   string
	IP   net.IP
}
