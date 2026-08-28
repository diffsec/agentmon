# Content inspection (`decision: inspect`)

`inspect` defers a policy verdict to an inspection of the content itself, rather
than deciding from a path, an argv or a destination. It is the policy grammar
for "allow this write, but not if it carries a credential".

**Status: the grammar is live; no inspection providers exist yet.** Every
inspect-bearing rule therefore resolves to an effective deny. See
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

`Policy.RequiresInspection()` reports whether any rule needs an inspector. A
server that cannot provide one should refuse to install such a policy rather
than run it, because every inspect-bearing rule would otherwise deny in a way
the operator did not write.

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
