# Serving policy

`agentmon policy serve` hands signed policy bundles to agents over HTTP. It is
the other half of the contract `policy.RemoteSource` was built against
(`docs/policy-sources.md`): the agent fetches with a conditional GET, the
server answers with the document and its detached signature, and the agent
verifies against its own trust store before installing.

```
agentmon policy serve \
  --dir /etc/agentmon/policies \
  --bindings /etc/agentmon/bindings.yaml \
  --trust-store /etc/agentmon/trust \
  --listen 0.0.0.0:8787 \
  --tls-cert server.pem --tls-key server-key.pem \
  --client-ca clients-ca.pem
```

## The server holds no signing key

Nothing in the serve path signs anything. Bundles are signed elsewhere -- with
`agentmon policy sign` on an offline machine, or by a KMS -- and the server
reads the `.yaml` and its `.yaml.sig` and hands both out unchanged.

That is the whole security argument. An attacker who owns the policy server can
serve any bytes they like and no agent will enforce them, because
`Manager.verifyBundle` checks the signature against the agent's local trust
store on the load path, whatever the source. `TestRoundTrip_UntrustedKeyIsRefused`
is that property as a test.

The server verifies too, at load, and refuses to serve a bundle that fails.
This check cannot replace the agent's and is not meant to: it turns a bad
bundle into a startup error on one host instead of a fleet that fails closed
against a document nobody can install. `--allow-unsigned` skips it for a
development loop and logs a warning per bundle.

## Bindings decide which agent gets which policy

```yaml
bindings:
  - name: prod-builders
    policy: strict.yaml
    match:
      tenants: ["acme"]
      hostnames: ["build-*"]
      users: ["ci"]
      tags: ["prod", "pci"]
  - name: fallback
    policy: baseline.yaml
```

First match wins, so order most specific first. A binding with no `match` block
is a catch-all.

An empty list leaves that field unconstrained and every non-empty field must
match, so adding a field narrows a binding and never widens it. A typo in a new
field then serves nothing rather than serving everything.

`tags` is all-of, unlike the others. A host carries a set of tags, so an any-of
test would let one tag out of ten select the binding, which is not what
`tags: [prod, pci]` reads as. `hostnames`, `users` and `tenants` are glob
patterns matched case-insensitively; `policy` must be a file name in the served
directory, never a path.

**No binding is a 404, not an empty policy.** The agent then keeps enforcing
what it has. Answering 200 with nothing would disable enforcement on every
agent that fell out of a binding.

### Where the selector comes from

The agent reports itself in headers, mirroring `internal/decisionctx`, which
already resolves these signals for Watchtower:

| Header | Query fallback |
|---|---|
| `X-Agentmon-Tenant` | `?tenant=` |
| `X-Agentmon-Hostname` | `?hostname=` |
| `X-Agentmon-User` | `?user=` |
| `X-Agentmon-Tags` (comma-separated) | `?tags=` |

The query fallback exists so a fetch can be reproduced with curl.

**None of this is authenticated.** It selects which policy an agent is offered,
never what that agent may do: an agent that lies about its hostname gets a
different signed document, and every rule in it is one the operator signed.
Authentication belongs at the transport, which is what `--client-ca` is for.

## Live update

`GET /v1/policy?wait=30s` holds the request until the bundle bound to that
agent changes, then answers 200 with the new document. A poll whose wait
elapses gets 304. `wait` is clamped to five minutes: a request held
indefinitely survives a dropped connection as a goroutine on the server and a
stalled poll on the agent, and neither end finds out.

A reload that changed some other tenant's policy does not wake this agent's
poll. Waking on every reload would hand each agent the document it already has,
on every change anywhere in the fleet.

The `ETag` is `sha256:` over the document, not a counter or an mtime, so two
servers behind a load balancer answer the same `If-None-Match` identically and
a restart does not invalidate every agent's cached copy.

## Delivering a new bundle

With `--watch` (the default) the server watches the policy directory through
`pkg/hotreload`, which also gives the staging path:

1. Write `newpolicy.yaml.sig` into `<dir>/.staging/`.
2. Write `newpolicy.yaml` into `<dir>/.staging/`.
3. After a 2s debounce the server verifies the signature and parses the
   document. A bundle that fails stays in staging and is never served.
4. A bundle that passes is moved into the live directory, signature first, and
   the next poll returns it.

Signature first is what makes step 3 meaningful: the live watcher never sees a
policy without the `.sig` that covers it.

Copying a signed pair straight into the live directory works too. The debounce
means the `.yaml` landing before the `.sig` is a transient failure rather than
a wrong answer, but staging is the path that has no window at all.

A failed reload keeps the previously loaded bundles in force and `/healthz`
reports `degraded` with a 503. Reporting `ok` there would hide a policy the
operator believes is live.

## mTLS

`--client-ca` sets `ClientAuth: RequireAndVerifyClientCert`. Anything weaker
(`RequestClientCert`, `VerifyClientCertIfGiven`) accepts a client that presents
nothing, which is every client an attacker controls.

`--client-ca` without `--tls-cert` is refused rather than ignored: the flag
reads as "require client certificates", and honouring it on a plaintext
listener is impossible, so accepting it would authenticate nothing while
looking like it authenticated everything.

## Not wired yet

Nothing selects a `RemoteSource` from agent configuration; that is the next
piece. Until then the round trip is exercised by
`internal/policyserve/roundtrip_test.go`, which drives a real `policy.Manager`
with `signing: enforce` against a real server.

`internal/server/server.go` still uses `credentials.NewServerTLSFromFile` for
the gRPC listener, which is one-way TLS with no `ClientCAs`. The mTLS here
covers the policy endpoint only.
