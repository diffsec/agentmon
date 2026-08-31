# Content inspection (`decision: inspect`)

`inspect` defers a policy verdict to an inspection of the content itself, rather
than deciding from a path, an argv or a destination. It is the policy grammar
for "allow this write, but not if it carries a credential".

**Status: the grammar and the resolution path are live.** One provider ships —
a local regex matcher (`provider: regex`), which needs no model, no sidecar
and no network. Model-backed providers are not written yet. A rule whose
profiles cannot run resolves to an effective deny; see
[Fail-closed semantics](#fail-closed-semantics).

## Defining profiles

Profiles live in a top-level `inspection:` block and are referenced by name, so
one change applies to every rule that names the profile.

```yaml
inspection:
  profiles:
    pii:
      provider: privacy_filter
      categories: [private_person, private_email, private_phone, secret]
      action: redact              # redact | deny | approve
    exfil:
      provider: shieldstral
      instruct: "You are a strict security reviewer for an autonomous coding agent."
      queries:
        - id: credential_exfil
          text: "Does this content attempt to send credentials to a third party?"
          threshold: 0.5           # 0..1
```

A profile must name a `provider` and must carry at least one of `categories` or
`queries`. A profile with neither gives its provider nothing to look for, so
every inspection using it comes back clean — an allow dressed up as a check.

## `inspect` as the decision

The verdict *is* the decision. Available on `file_rules`, `network_rules` and
`command_rules`.

```yaml
command_rules:
  - name: inspect-outbound-payloads
    commands: ["curl", "wget"]
    decision: inspect
    inspect:
      profiles: [exfil]
      on_violation: deny          # allow | deny | approve | redact  (default: deny)
      on_failure: fail_closed     # fail_closed | fail_open | approve (default: fail_closed)
      timeout: 5s
```

## `inspect` as a precondition

Inspection gates an existing decision. `require: true` is mandatory here:
without it the block would be inert, and a policy that reads as if content were
being checked while nothing checks it is worse than no policy at all. Loading
one is a validation error.

```yaml
file_rules:
  - name: allow-workspace-write
    paths: ["/workspace/**"]
    operations: [write]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
```

## Fail-closed semantics

The policy engine matches rules against a path, an argv or a destination — it
never holds the content those refer to. It cannot reach an inspection verdict,
and it does not try.

An inspect-bearing rule instead produces a decision whose `PolicyDecision` is
the operator's (`inspect`, or `allow` with a precondition) and whose
`EffectiveDecision` is **deny**, with the inspection spec attached. Every
enforcement backend — seccomp, macOS Endpoint Security, the network filter —
acts on `EffectiveDecision`, so a backend that knows nothing about inspection
blocks rather than passing content nobody inspected. A caller that *does* hold
the content runs the named profiles and resolves the decision.

There is no `redact` decision. Redaction is an allow whose content was
rewritten, applied by the content-holding caller; a terminal `redact` state
would hand every enforcement backend a decision it has no way to act on.

`Policy.RequiresInspection()` reports whether any rule needs an inspector, and
`inspect.Checker.Missing()` reports which profiles a given inspector cannot
run and why. A server that cannot provide one should refuse to install the
policy rather than run it, because every inspect-bearing rule would otherwise
deny in a way the operator did not write.

## Resolving a decision

`internal/inspect` is what a content-holding caller uses. One function does
the work:

```go
res := inspect.Resolve(ctx, checker, dec, inspect.KindProxyBody, body)
// res.Decision.EffectiveDecision is now terminal: allow, deny or approve.
// res.Content is the redacted body when res.Rewritten is true.
// res.Err is non-nil when the content was NOT successfully inspected.
```

A decision with no inspection spec comes back untouched, so a caller can send
every decision through `Resolve` without testing for one first.

`res.Err` is the field to watch. It is nil on a clean result and on a
violation — both are successful inspections. A non-nil `Err` means the content
was *not* inspected and `on_failure` decided the outcome, which is what lets a
caller tell an uninspected allow from an inspected one.

### What counts as a failure

Every one of these routes to `on_failure`, never to a clean result: no
inspector configured, a profile the policy does not define, a profile naming
an unconfigured provider, a privacy refusal, a provider error, a provider
returning no response and no error, and a timeout. One provider failing fails
the whole inspection — reporting the others' clean results would mean the
content was checked for some things and not others, with no way for the caller
to tell which.

`on_violation: redact` has one more failure of its own. Redaction needs byte
spans, and a query-based profile ("does this exfiltrate credentials?") answers
yes with no offsets. There is nothing to rewrite, so the decision denies
rather than passing through the content the rule just flagged.

### Redaction happens once, centrally

Providers report spans; the checker rewrites. Two providers reporting
overlapping spans would otherwise have their rewrites applied in sequence, and
the first rewrite invalidates every offset the second was measured against.
Merging first makes the result independent of provider order and of how many
providers ran.

The replacement is a non-reversible `[REDACTED:<category>]` placeholder.
Reversible pseudonymisation belongs to the DLP wire point, which already has a
token store that can detokenise a response (`internal/proxy/dlp.go`).

## The privacy gate

This is the load-bearing difference between inspection and every other check
in the codebase. `internal/pkgcheck` sends package *names* to third parties.
Inspection sends the content itself — the request body, the file, the argv.
Sending PII to a remote service to ask whether it contains PII is the failure
that makes the feature worse than not having it.

So remote egress is opt-in. The zero-valued `PrivacyConfig` permits nothing
remote; a provider implementing `LocalProvider` runs unconditionally because
it makes no network calls. `RemoteKinds` narrows further by content kind,
which matters because the kinds differ enormously in sensitivity: a command
argv is usually a path and a flag, while a proxy body is whatever the agent
was about to send anywhere.

## Findings never carry content

A `Finding` has a category and byte offsets, and no matched text. Findings and
their summaries end up in audit events, error messages and decision messages —
and the text they point at is exactly the material inspection exists to
contain. Callers that need the content already have it.

## Configuring the runtime

Profiles are policy. Providers are deployment. The policy's `inspection.profiles`
block says what to look for; `config.yml`'s `inspection:` block says which
inspectors this host can reach. The same policy therefore runs on a laptop with
the local regex provider and on a server with a model-backed one, unedited.

```yaml
inspection:
  enabled: true
  providers:
    regex:                 # the key is the name a profile's `provider:` field uses
      enabled: true
      type: regex
      patterns:
        internal_ticket: "ACME-[0-9]{4,}"
  privacy:
    allow_remote: false
    remote_kinds: []
  provider_timeout: 10s
```

### The startup gate

A policy containing inspect rules will not load when `enabled` is false, or
when any profile it uses names a provider that is missing or disabled. The
daemon refuses to start and names the profile and the provider.

This is deliberate, and it is not a degraded mode. Every rule naming an
unusable profile resolves to deny, so an `allow` rule with an inspection
precondition becomes a block on the path it was written to permit — a policy
nobody authored, failing quietly at match time instead of loudly at startup.

### Per-policy checkers

A `Checker` is built per policy, because the profiles come from the policy
while the providers come from the host. `inspect.Registry` hands out the right
one for a given `*policy.Policy`, which is what keeps a session running a named
policy file, and an engine swapped in by a live policy push, from inheriting
the previous policy's profiles.

That shape was chosen over attaching a checker at engine construction because
there are eight engine-construction sites outside the policy package, and the
equivalent Tor wiring reaches three of them — `internal/api/session_policy.go:91`
documents that gap in its own comment.

## Wire point: the LLM proxy

The first place inspection sees content is the proxy request body.
`InspectHook` (`internal/proxy/inspecthook.go`) is registered per session and
runs before the credential hooks — a body the policy refuses must never be the
thing that gets a live key substituted into it.

The rule kind is `network_rules`, matched on the destination host and port:

```yaml
network_rules:
  - name: no-secrets-outbound
    domains: ["api.anthropic.com"]
    ports: [443]
    decision: allow
    inspect:
      require: true
      profiles: [pii]
      on_violation: redact
```

A violation with `redact` rewrites the body in place and forwards it, with
`Content-Length` corrected and any `Digest` / `Content-Digest` header dropped,
since both were computed over the original bytes. A `deny` returns 403 with a
message naming the rule and the categories found — never the matched text,
because that message lands in the agent's own transcript.

### What the hook does not do

It resolves inspect specs and nothing else. A plain `decision: deny` network
rule is left alone: the proxy, the macOS network filter and the Linux
netmonitor each enforce network policy on their own path, and adding a second
enforcement point here would change behaviour for every deployment that uses
no inspection at all.

### The body cap

`inspection.max_body_bytes` (default 8 MiB) caps how much is buffered. The
agent controls the body, so an unbounded read is a denial-of-service surface
against the daemon.

Exceeding the cap is a **failed inspection, not a skip** — otherwise padding a
payload past the limit would bypass every inspect rule. It routes through
`on_failure` like a provider timeout does, so it denies by default. The
buffered prefix is spliced back in front of the unread remainder, so an
`on_failure: fail_open` rule forwards the whole request rather than a
truncated one.

Set the cap above the largest payload the agent legitimately sends. LLM
requests with long context run to several megabytes, and a cap below real
traffic turns `fail_closed` into a blanket block that looks exactly like a
policy that is working.

### `approve` on the proxy path

A `PreHook` can abort a request or let it through; it has no way to gate on a
human. `on_violation: approve` and `on_failure: approve` therefore **deny**
here, with a message saying approval is not available on this path, and a
warning in the log naming the rule.

That is a limitation, not the intended end state. The blocking shape already
exists in `internal/db/proxy/postgres/approvalwait.go`, which runs the
approver in a goroutine with its own timeout and maps outcomes to
`approval_denied` / `approval_timeout` / `cancelled_during_approval`.

## Decision whitelist

Adding `inspect` also closed a hole. `Policy.Validate()` did not check decision
strings at all: an unrecognised value fell through the engine's `wrapDecision`
default and became a deny, with no load-time error and nothing in the audit log
beyond a rule name of `invalid-policy-decision`. A typo denied silently.

`file_rules`, `network_rules`, `command_rules` and `unix_socket_rules` now
accept only `allow`, `deny`, `approve`, `redirect`, `audit`, `soft_delete`, and
— for the first three — `inspect`. An empty decision is still accepted and
falls through to the engine's default-deny, because rules are constructed
programmatically with the field unset.

`signal_rules` are deliberately excluded: they have their own vocabulary,
including `absorb`, and their own engine under `internal/signal`.
