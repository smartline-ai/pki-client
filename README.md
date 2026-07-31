# pki-client

The client half of SmartLine's internal PKI: a daemon uses it to obtain its own
X.509 certificate from the Control Plane and to keep that certificate alive
without restarting.

```go
import pkiclient "github.com/smartline-ai/pki-client"
```

```bash
go get github.com/smartline-ai/pki-client@v0.3.0
```

No `GOPRIVATE` needed — this module is public. The services that consume it are
not, but that does not affect fetching this one.

## What it does

A participant proves it is allowed to exist with a **single-use join token**,
sends a CSR, and receives a CA-signed leaf. From then on it renews itself.

```
  read token ──▶ generate key ──▶ CSR ──▶ POST /v1/principals/join
                                            │
                              verify the returned leaf matches the key
                                            │
                                   atomic write to disk
                                            │
                        renew at 1/3 of lifetime remaining, hot-swapped
```

Three kinds of participant, differing only in what their certificate may
assert:

| Kind | Leaf | SAN |
|---|---|---|
| `node` | serverAuth + clientAuth | exactly one RFC1918 address |
| `service` | serverAuth + clientAuth | exactly one address, pinned in the token when it was minted |
| `client` | clientAuth only | none |

The `service` rule is the load-bearing one. It allows a **public** address —
some machines have no private interface — but only the address the operator
pinned at mint time, never one asserted by the requester. At join time the
requester has no certificate yet, so its request body is simply whatever
someone chose to write in it.

## Usage

`Ensure` is the whole entry point. Call it before anything reads the
certificate from disk.

```go
deps := pkiclient.Deps{
    Mode:          cfg.Announce.Mode,        // "control_plane" enables join+renew
    PKIURL:        cfg.Announce.PKIURL,
    JoinTokenFile: cfg.Announce.JoinTokenFile,
    CAFile:        cfg.TLS.CAFile,
    CertFile:      cfg.TLS.CertFile,
    KeyFile:       cfg.TLS.KeyFile,
    Identity: pkiclient.Identity{
        Kind: pkiclient.KindService,
        CN:   "builder-1",
        IP:   net.ParseIP("203.0.113.10"),   // nil for KindClient
    },
    Log: log,
    Now: time.Now,
}

if err := pkiclient.Ensure(ctx, deps); err != nil {
    return fmt.Errorf("certificate: %w", err)
}

src := &pkiclient.CertSource{}
if err := src.Load(deps.CertFile, deps.KeyFile); err != nil {
    return err
}
go pkiclient.RunRenewal(ctx, deps, src, 6*time.Hour)

tlsCfg := &tls.Config{GetCertificate: src.Get}   // renewal swaps underneath
```

## Four behaviours worth knowing before you change anything

Each exists because of a specific failure, and each has a test named after it.

**`Mode` gates everything.** Anything other than `"control_plane"` skips join
and renewal entirely. This is what lets you roll out new code to a running
fleet without any certificate moving: the binary lands, the certificate is
untouched, and cutover stays a separate deliberate act.

**A valid certificate short-circuits join.** `Ensure` returns early rather than
re-joining, so restarts and redeploys cost nothing and burn no tokens.

**An unreadable certificate refuses rather than re-joins.** A corrupt file
could look like an absent one; treating it that way would spend a single-use
token on a join that was never needed. It fails loudly instead.

**A split key pair is detected and repaired.** A certificate that is valid on
its own but does not match the key beside it will fail the TLS handshake, and
`os.Stat` cannot see the difference — only `tls.LoadX509KeyPair` can. When that
happens the pair is re-joined. `LoadOrCreateKey` never overwrites an existing
key, so this cannot destroy a key a working certificate depended on.

## Renewal

`NeedsRenewal` triggers at **one third of the lifetime remaining**, not at a
fixed number of days, so it scales with whatever TTL the CA issues. Renewal
replaces the pair on disk atomically and pushes it into `CertSource`; existing
connections are unaffected and no restart is required.

## Versions

`v0.1.0` and `v0.2.0` declare the wrong module path in their own `go.mod` and
cannot be consumed without a `replace` directive. **Start at `v0.3.0`.**
