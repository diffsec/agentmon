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

### The sidecar provider

`type: sidecar` calls an HTTP service over the agentmon inspection contract.
The contract is the boundary, not the model: anything serving these two
endpoints works, which is what keeps the choice of inference runtime out of
this codebase.

```yaml
inspection:
  enabled: true
  providers:
    sidecar:
      enabled: true
      type: sidecar
      api_key_env: AGENTMON_INSPECT_TOKEN   # optional; sent as a bearer token
      options:
        base_url: http://127.0.0.1:8731
  privacy:
    allow_remote: true      # required: a sidecar is not a local provider
```

```
POST {base}/v1/inspect/pii
  -> {"text": "...", "categories": ["private_email", ...]}
  <- {"spans": [{"start": 0, "end": 17, "category": "private_email", "score": 0.99}],
      "redacted_text": "..."}

POST {base}/v1/inspect/safety
  -> {"document": "...", "instruct": "...", "queries": [{"id": "exfil", "text": "..."}]}
  <- {"results": [{"id": "exfil", "score": 0.61, "verdict": true}]}
```

A profile with `categories` calls the PII endpoint, one with `queries` calls
safety, one with both calls both and merges.

**Span offsets are bytes into the UTF-8 encoding of the text that was sent**,
half-open `[start, end)`. This is the part of the contract that fails
silently when it is wrong: Privacy Filter's own decoder works in *token*
offsets, so a sidecar forwarding those unconverted returns spans that look
entirely plausible and cut the wrong bytes out of a request body. A span that
is out of range, inverted, empty or landing inside a UTF-8 sequence is an
**error**, not a dropped finding — the provider and the daemon disagreeing
about offsets makes every other span in that response suspect too.

Three more things the provider refuses rather than works around: a category
outside its taxonomy (rejected before any content is sent), a safety result
for a query nobody asked (dropped, so a sidecar cannot inject findings the
policy did not author), and a query left unanswered (an error, because
reporting the rest as clean means the profile checked less than it said).

The profile's `threshold` decides a safety verdict whenever the sidecar
returns a score. The sidecar's own `verdict` field is its default operating
point and only applies when no score is present; an operator who wrote `0.9`
must not be overridden by a service defaulting to `0.5`.

A sidecar is **not** a `LocalProvider`, even bound to `127.0.0.1`. Content
sent to it leaves the process, and nothing in an HTTP URL proves where it
resolves to, so `privacy.allow_remote` must be on for it to run at all.

### The Privacy Filter provider

`type: privacy_filter` runs OpenAI Privacy Filter in-process through ONNX
Runtime. It is a `LocalProvider`, so the privacy gate lets it see content
without `allow_remote` — which is the whole point: inspecting text for PII by
shipping it to a remote service is the failure this design exists to avoid.

```yaml
inspection:
  enabled: true
  providers:
    privacy_filter:
      enabled: true
      type: privacy_filter
      options:
        allow_download: true
        intra_op_threads: 2
```

It detects eight categories: `account_number`, `private_address`,
`private_date`, `private_email`, `private_person`, `private_phone`,
`private_url`, `secret`. A profile naming anything else is an error rather
than a clean result.

**Two host requirements.** `libonnxruntime` must be installed (or
`options.library_path` set), and the model — 917MB — must be cached.
`allow_download` is false by default: fetching that on first start looks like
a hang, and an air-gapped host needs a way to refuse. Files are verified
against SHA-256 digests pinned to an upstream commit, so the download source
does not matter.

**Context limit.** Text longer than the model's 128,000-token window is
refused, not truncated. Inspecting a prefix and reporting the rest clean would
let an agent bury anything past the limit. It routes through `on_failure`,
which denies by default. Chunking long inputs would lift the limit and is not
implemented.

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

**Rules match the resolved upstream, not the proxy.** The agent is configured
to talk to this proxy on `127.0.0.1`, so the request's `Host` is the proxy's
own listen address. A rule naming `api.anthropic.com` matches because the
proxy records the destination it resolved from the dialect before hooks run
(`AttrUpstreamURL`).

### Reversible redaction

What `redact` writes depends on `dlp.mode`, reusing that knob rather than
adding another, because the semantics already match.

With `dlp.mode: tokenize`, a finding is replaced by a reversible `TOK_<hex>`
pseudonym from the proxy's DLP token store, and the response detokenizer puts
the real value back before the agent sees it. The model never sees the value;
everything downstream still works.

In any other mode the replacement is `[REDACTED:<category>]`. That is safe —
it retains nothing — but it destroys the value for everything downstream, not
just for the model: the reply comes back about an address that no longer
exists anywhere.

Both paths mint from the **same** token store the regex DLP patterns use. One
value gets one token whether a pattern or an inspection profile found it, and
one `Detokenize` pass reverses both. Two stores would mean a value found by
both got two tokens and the response detokenizer would only know one.

The store holds originals in memory for the life of the session. That is the
exposure `dlp.mode: tokenize` already accepts, which is why tokenization is
opt-in and the placeholder is the default.

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
