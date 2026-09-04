# Where a policy comes from

`policy.Manager` loads a policy once and caches it. Until now the load was a
single function: resolve a path in the policy directory, read it, check the
manifest, verify the signature, parse, validate. Serving a policy from
somewhere else meant a second load path, and a second load path is a second
set of trust decisions to keep in agreement.

Fetching is now behind an interface. Everything after the fetch is unchanged
and shared, so a policy served over HTTP clears the same bar as one read from
disk rather than an approximation of it.

```go
type Source interface {
    Fetch(ctx context.Context) (*Bundle, error)
    Describe() string
}

type Bundle struct {
    Data      []byte // the policy YAML
    Signature []byte // the detached .sig JSON, nil when there is none
    Name      string // a path, or a URL with its query stripped
    Version   string // opaque change token; the ETag for HTTP
}
```

`Manager.SetSource` swaps it. Nil goes back to the local directory, which is
what every existing deployment gets without changing anything.

## The signature travels with the document

This is what forced the split. Verification was path-based:
`signing.VerifyPolicyBytes(data, path+".sig", ts)` reads a file next to the
policy. A policy pushed over the wire carries its signature in the same
message, and one fetched from a server carries it in a header — neither has a
path to read.

`signing.VerifyBytes(policyBytes, sigData, ts)` takes the signature already in
memory. Every verification in the tree now funnels through it or through
`signing.Verify`: the disk load path, the CLI, the API's session loads, and
the Watchtower push hook, which previously assembled its own trust-store
lookup and `ed25519.Verify` call.

An empty signature is `missing_signature`, not "nothing to check" — otherwise
`signing: enforce` would pass anything a server chose not to sign.

## FileSource

Reads the policy directory, exactly as before. It also owns the SHA256SUMS
manifest check, because that check is a property of the local directory: it
maps a basename to a digest, and a bundle that never came from that directory
can never be listed in it.

A missing `.sig` is not a fetch error. The signing mode decides whether an
unsigned policy may load; reporting the absence as a read failure would turn
`signing: off` into a hard error for every policy nobody signed.

## RemoteSource

Fetches over HTTP with a conditional GET, modelled on
`internal/threatfeed/syncer.go` — the in-tree precedent for this shape.

```go
src, err := policy.NewRemoteSource("https://policy.example/v1/policy?tenant=acme")
src.Wait = 30 * time.Second   // long-poll; a server that ignores it answers at once
m.SetSource(src)
```

**The signature is a header, `X-Agentmon-Policy-Signature`**, not a field in a
JSON envelope. The body is then the exact bytes that were signed. Reading the
document out of an envelope would mean re-encoding before verification, and
any difference in that round trip invalidates a signature that was fine.

**304 is distinct from an empty response.** `Fetch` returns
`policy.ErrNotModified`, and `Manager.ReloadContext` keeps the policy it has.
Installing an error there would take enforcement down on the first quiet poll.
Before anything is loaded, a 304 is a broken server rather than a quiet one —
there is nothing to keep — so it surfaces.

**The read is capped** at `DefaultRemoteMaxBytes` (4 MiB), reading one byte
past the cap so truncation is detectable at all. A cut document either fails
to parse confusingly or, worse, parses with the rules after the cut missing.
Exceeding the cap is an error, never a prefix.

**The ETag is recorded only after the whole body is read.** Recording it on a
failed or truncated read would make the next conditional GET answer 304 for a
document the agent never installed — so it would keep enforcing the old policy
while every poll reported success.

**Errors carry the status, not the body, and not the query.** A policy
endpoint can hold a token in its query or its userinfo, and a server's error
body can echo the request back. Both reach the log, so `sanitizeSourceURL`
strips query, fragment and userinfo, and only the HTTP status is reported.

`Wait` appends to an existing query rather than replacing it, so a tenant
selector and a long-poll duration coexist.

## The trust boundary is the key, not the transport

The server is untrusted. A compromised policy server cannot push a policy the
agent will enforce, because the signature is verified against the local trust
store on the load path — the same check, in the same place, whatever the
source. That is the reason the split keeps verification on the Manager rather
than letting each source do its own.

## The server

`agentmon policy serve` is the other half of the contract: it answers the
conditional GET, carries the signature in `X-Agentmon-Policy-Signature`, and
holds a `wait=` poll open until the bundle changes. It holds no signing key.
See `docs/policy-server.md`.

`internal/policyserve/roundtrip_test.go` drives a real `Manager` with
`signing: enforce` against a real server, including the case that matters most:
a bundle signed with a key the agent does not trust does not install.

## Not wired yet

Nothing selects a `RemoteSource` from agent configuration. That is the next
piece; until then a `RemoteSource` is installed by calling
`Manager.SetSource`.
