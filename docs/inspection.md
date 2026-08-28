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
