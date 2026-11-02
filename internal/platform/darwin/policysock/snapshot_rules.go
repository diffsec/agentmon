//go:build darwin

package policysock

import (
	"log/slog"
	"sort"
	"strings"

	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/internal/signal"
	"github.com/diffsec/agentmon/pkg/types"
)

// unixSocketSnapshotRules sends the policy's unix_socket_rules, one entry for
// each path. The extension matches them with the same glob rules as file
// paths: "*" stops at "/", and "**" does not.
func unixSocketSnapshotRules(rules []policy.UnixSocketRule) []SnapshotUnixSocketRule {
	var out []SnapshotUnixSocketRule
	for _, r := range rules {
		ops := make([]string, 0, len(r.Operations))
		for _, op := range r.Operations {
			ops = append(ops, strings.ToLower(strings.TrimSpace(op)))
		}
		for _, path := range r.Paths {
			out = append(out, SnapshotUnixSocketRule{
				Name:       r.Name,
				Pattern:    path,
				Operations: ops,
				Action:     r.Decision,
			})
		}
	}
	return out
}

// signalSnapshotRules sends the policy's signal_rules with each signal name
// and group expanded to its number on this machine. The extension has no
// table of signal names.
//
// policy.NewEngine already compiled these rules, so a signal that does not
// parse here cannot occur. If one does, the rule is sent without it, and the
// log says so.
func signalSnapshotRules(rules []policy.SignalRule) []SnapshotSignalRule {
	var out []SnapshotSignalRule
	for _, r := range rules {
		out = append(out, SnapshotSignalRule{
			Name:    r.Name,
			Signals: expandSignals(r.Name, r.Signals),
			Target:  strings.ToLower(strings.TrimSpace(r.Target.Type)),
			Pattern: r.Target.Pattern,
			Min:     r.Target.Min,
			Max:     r.Target.Max,
			Action:  macOSSignalAction(r.Decision, r.Fallback),
		})
	}
	return out
}

func expandSignals(rule string, specs []string) []int {
	seen := map[int]struct{}{}
	for _, spec := range specs {
		var sigs []int
		if signal.IsSignalGroup(spec) {
			g, err := signal.ExpandSignalGroup(spec)
			if err != nil {
				slog.Error("policy socket: signal rule has an unknown group", "rule", rule, "group", spec, "error", err)
				continue
			}
			sigs = g
		} else {
			s, err := signal.SignalFromString(spec)
			if err != nil {
				slog.Error("policy socket: signal rule has an unknown signal", "rule", rule, "signal", spec, "error", err)
				continue
			}
			sigs = []int{s}
		}
		for _, s := range sigs {
			seen[s] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Ints(out)
	return out
}

// macOSSignalAction maps a signal rule's decision to one that the extension
// can enforce. ES can allow or deny a signal, and nothing else.
//
//   - allow and audit allow the signal.
//   - deny denies it. The sender gets EPERM.
//   - absorb denies it. On Linux the sender sees success. ES cannot do that,
//     so the sender gets EPERM.
//   - approve denies it. No approval dialog exists for signals yet.
//   - redirect cannot be done. As signal.ApplyFallback does on a platform
//     that cannot do it, the rule's fallback applies, or audit without one.
//
// `agentmon policy validate` warns about absorb, approve and redirect.
func macOSSignalAction(decision, fallback string) string {
	switch signal.DecisionAction(strings.ToLower(strings.TrimSpace(decision))) {
	case signal.DecisionAllow:
		return string(types.DecisionAllow)
	case signal.DecisionAudit:
		return string(types.DecisionAudit)
	case signal.DecisionRedirect:
		if fallback == "" || signal.DecisionAction(strings.ToLower(fallback)) == signal.DecisionRedirect {
			return string(types.DecisionAudit)
		}
		return macOSSignalAction(fallback, "")
	default:
		return string(types.DecisionDeny)
	}
}
