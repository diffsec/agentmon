//go:build darwin

package capabilities

import (
	"os/exec"

	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/diffsec/agentmon/internal/platform/helperbin"
)

func buildDarwinDomains(caps map[string]any, esfDetail string) []ProtectionDomain {
	esf, _ := caps["esf"].(bool)
	networkExt, _ := caps["network_extension"].(bool)
	hasMacwrap := checkMacwrap()

	macwrapDetail := "not found"
	if hasMacwrap {
		macwrapDetail = "dynamic seatbelt"
	}

	return []ProtectionDomain{
		{
			Name: "File Protection", Weight: WeightFileProtection,
			Backends: []DetectedBackend{
				{Name: "esf", Available: esf, Detail: esfDetail, Description: "Endpoint Security Framework", CheckMethod: "sysext"},
			},
		},
		{
			Name: "Command Control", Weight: WeightCommandControl,
			Backends: []DetectedBackend{
				{Name: "esf", Available: esf, Detail: esfDetail, Description: "process execution control", CheckMethod: "sysext"},
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "policy-driven exec restriction", CheckMethod: "binary"},
			},
			Active: func() string {
				if esf {
					return "esf"
				}
				if hasMacwrap {
					return "dynamic-seatbelt"
				}
				return ""
			}(),
		},
		{
			Name: "Network", Weight: WeightNetwork,
			Backends: []DetectedBackend{
				{Name: "network-extension", Available: networkExt, Detail: networkExtDetail, Description: "network filtering", CheckMethod: "entitlement"},
			},
		},
		// sandbox-exec is deliberately absent from Command Control and Isolation.
		// The binary ships with macOS, but agentmon never invokes it --
		// platform.Sandbox() has no callers anywhere -- so counting it awarded
		// WeightCommandControl + WeightIsolation for a mechanism that never runs.
		{
			// No resource-limit enforcement exists on macOS. There is no launchd
			// limits implementation anywhere in the tree, and DarwinLimiter --
			// which only wraps setrlimit, and so can constrain the calling
			// process rather than a spawned session -- is never instantiated by
			// the server. Reporting this as available scored the full
			// WeightResourceLimits for enforcement that does not run.
			Name: "Resource Limits", Weight: WeightResourceLimits,
			Backends: []DetectedBackend{
				{Name: "rlimit", Available: false, Detail: "not wired: setrlimit constrains only the calling process, and no per-session limiter is installed", Description: "resource limits", CheckMethod: "builtin"},
			},
		},
		{
			Name: "Isolation", Weight: WeightIsolation,
			Backends: []DetectedBackend{
				{Name: "dynamic-seatbelt", Available: hasMacwrap, Detail: macwrapDetail, Description: "deny-default sandbox", CheckMethod: "binary"},
			},
			Active: func() string {
				if hasMacwrap {
					return "dynamic-seatbelt"
				}
				return ""
			}(),
		},
	}
}

// darwinCaps maps sysext liveness onto the capability map. Kept pure so the
// esf/esf_activated mapping — the exact regression #441 fixed — is testable
// without subprocesses.
func darwinCaps(l darwin.SysExtLiveness) map[string]any {
	return map[string]any{
		"sandbox_exec":      true,
		"esf":               l.Running,
		"esf_activated":     l.Activated,
		"esf_probe_failed":  l.ProbeFailed,
		"network_extension": checkNetworkExtension(),
		"lima_available":    checkLima(),
	}
}

// Detect runs platform-specific detection and returns unified result.
func Detect() (*DetectResult, error) {
	liveness := darwin.CheckSysExtLiveness()
	caps := darwinCaps(liveness)

	mode, _ := selectDarwinMode(caps)
	domains := buildDarwinDomains(caps, liveness.Detail)
	score := ComputeScore(domains)

	var available, unavailable []string
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Available {
				available = append(available, b.Name)
			} else {
				unavailable = append(unavailable, b.Name)
			}
		}
	}

	tips := GenerateTipsFromDomains(domains)

	return &DetectResult{
		Platform:        "darwin",
		SecurityMode:    mode,
		ProtectionScore: score,
		Domains:         domains,
		Capabilities:    caps,
		Summary:         DetectSummary{Available: available, Unavailable: unavailable},
		Tips:            tips,
	}, nil
}

// checkNetworkExtension reports whether NetworkExtension filtering is active.
//
// It is not, and this is not a detection limitation: the system extension never
// enters NetworkExtension mode. main.swift ends at dispatchMain() without ever
// calling NEProvider.startSystemExtensionMode(), so FilterDataProvider and
// DNSProxyProvider are never instantiated and no NEFilterManager or
// NEDNSProxyManager configuration is installed. Until that is wired up, all
// network and DNS policy is unenforced on macOS.
func checkNetworkExtension() bool {
	return false
}

// networkExtDetail explains the unavailability above in `agentmon detect`
// output, so the gap is visible rather than an empty cell.
const networkExtDetail = "not started: the system extension never enters NetworkExtension mode, so network and DNS rules are unenforced"

func checkLima() bool {
	// Check if limactl is available
	_, err := exec.LookPath("limactl")
	return err == nil
}

func checkMacwrap() bool {
	// helperbin.Resolve, not exec.LookPath: agentmon-macwrap ships inside
	// AgentMon.app/Contents/MacOS, which is not on PATH for a launchd-started
	// daemon. PATH-only lookup reported "not found" for a wrapper that was
	// present and working, understating the protection score.
	return helperbin.Resolve("agentmon-macwrap") != ""
}

func selectDarwinMode(caps map[string]any) (string, int) {
	if esf, _ := caps["esf"].(bool); esf {
		return "esf", 90
	}
	if lima, _ := caps["lima_available"].(bool); lima {
		return "lima", 85
	}
	hasMacwrap := checkMacwrap()
	if hasMacwrap {
		return "dynamic-seatbelt", 65
	}
	// No fallback. sandbox-exec used to be reported here with a score of 60,
	// but nothing invokes it: platform.Sandbox() has no callers, so
	// darwin/sandbox.go and its SBPL machinery never run. Naming it as the
	// active security mode advertised isolation that does not exist.
	return "none", 0
}
