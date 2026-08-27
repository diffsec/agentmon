//go:build darwin

package capabilities

import (
	"strings"
	"testing"

	darwin "github.com/diffsec/agentmon/internal/platform/darwin"
)

func TestSelectDarwinMode(t *testing.T) {
	hasMacwrap := checkMacwrap()

	tests := []struct {
		name         string
		caps         map[string]any
		wantMode     string
		wantScore    int
		needsMacwrap bool
	}{
		{"esf wins", map[string]any{"esf": true, "lima_available": true}, "esf", 90, false},
		{"lima second", map[string]any{"esf": false, "lima_available": true}, "lima", 85, false},
		{"dynamic seatbelt", map[string]any{"esf": false, "lima_available": false}, "dynamic-seatbelt", 65, true},
		// With no ESF, no Lima and no macwrap there is no enforcement at all.
		// This used to report "sandbox-exec" scoring 60, but nothing invokes
		// sandbox-exec -- platform.Sandbox() has no callers.
		{"no enforcement available", map[string]any{"esf": false, "lima_available": false}, "none", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.needsMacwrap && !hasMacwrap {
				t.Skip("agentmon-macwrap not in PATH")
			}
			if !tt.needsMacwrap && hasMacwrap {
				if tt.wantMode == "none" {
					t.Skip("macwrap is in PATH, this tests the no-macwrap path")
				}
			}
			mode, score := selectDarwinMode(tt.caps)
			if mode != tt.wantMode {
				t.Errorf("selectDarwinMode() mode = %q, want %q", mode, tt.wantMode)
			}
			if score != tt.wantScore {
				t.Errorf("selectDarwinMode() score = %d, want %d", score, tt.wantScore)
			}
		})
	}
}

func TestDetect_Darwin(t *testing.T) {
	result, err := Detect()
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	if result.Platform != "darwin" {
		t.Errorf("Platform = %q, want darwin", result.Platform)
	}

	// Should have macOS-specific capability keys
	expectedKeys := []string{"sandbox_exec", "esf", "esf_activated", "esf_probe_failed", "network_extension"}
	for _, key := range expectedKeys {
		if _, exists := result.Capabilities[key]; !exists {
			t.Errorf("Capabilities missing key %q", key)
		}
	}

	// sandbox_exec should always be true (built into macOS)
	if se, ok := result.Capabilities["sandbox_exec"].(bool); !ok || !se {
		t.Error("sandbox_exec should be true")
	}
}

func TestBuildDarwinDomains_ESFDetail(t *testing.T) {
	caps := map[string]any{"esf": false, "network_extension": false}
	detail := "activated but not running (state: spawn scheduled, last exit: exit code 1)"
	domains := buildDarwinDomains(caps, detail, "unused")

	found := 0
	for _, d := range domains {
		for _, b := range d.Backends {
			if b.Name != "esf" {
				continue
			}
			found++
			if b.Available {
				t.Errorf("domain %q: esf Available = true, want false", d.Name)
			}
			if !strings.Contains(b.Detail, "not running") {
				t.Errorf("domain %q: esf Detail = %q, want liveness detail", d.Name, b.Detail)
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d esf backends, want 2 (File Protection, Command Control)", found)
	}
}

func TestDarwinCaps_LivenessMapping(t *testing.T) {
	tests := []struct {
		name     string
		liveness darwin.SysExtLiveness
		wantESF  bool
		wantAct  bool
		wantPF   bool
	}{
		{"activated but not running is the #441 case", darwin.SysExtLiveness{Activated: true, Running: false}, false, true, false},
		{"running implies esf", darwin.SysExtLiveness{Activated: true, Running: true}, true, true, false},
		{"not activated", darwin.SysExtLiveness{}, false, false, false},
		{"probe failure surfaces", darwin.SysExtLiveness{Activated: true, ProbeFailed: true}, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := darwinCaps(tt.liveness, darwin.ContentFilterState{})
			if got := caps["esf"].(bool); got != tt.wantESF {
				t.Errorf("esf = %v, want %v", got, tt.wantESF)
			}
			if got := caps["esf_activated"].(bool); got != tt.wantAct {
				t.Errorf("esf_activated = %v, want %v", got, tt.wantAct)
			}
			if got := caps["esf_probe_failed"].(bool); got != tt.wantPF {
				t.Errorf("esf_probe_failed = %v, want %v", got, tt.wantPF)
			}
		})
	}
}

// TestNetworkExtensionState pins the two-condition check behind the Network
// domain's score. Before the content filter was wired up this was a hardcoded
// false; the risk now runs the other way, so each case that must NOT score is
// listed explicitly.
func TestNetworkExtensionState(t *testing.T) {
	running := darwin.SysExtLiveness{Activated: true, Running: true}

	tests := []struct {
		name        string
		liveness    darwin.SysExtLiveness
		filter      darwin.ContentFilterState
		wantActive  bool
		detailMatch string
	}{
		{
			name:        "configured, enabled and running",
			liveness:    running,
			filter:      darwin.ContentFilterState{Installed: true, Enabled: true},
			wantActive:  true,
			detailMatch: "active",
		},
		{
			// The provider class is registered but macOS never instantiates it
			// without a configuration, so nothing filters.
			name:        "no filter configuration",
			liveness:    running,
			filter:      darwin.ContentFilterState{},
			wantActive:  false,
			detailMatch: "network-filter enable",
		},
		{
			// Indistinguishable from "no configuration" at the provider:
			// startFilter is not called either way.
			name:        "configuration present but disabled",
			liveness:    running,
			filter:      darwin.ContentFilterState{Installed: true},
			wantActive:  false,
			detailMatch: "disabled",
		},
		{
			// A configuration pointing at an extension that is not running
			// filters nothing.
			name:        "extension not running",
			liveness:    darwin.SysExtLiveness{Activated: true},
			filter:      darwin.ContentFilterState{Installed: true, Enabled: true},
			wantActive:  false,
			detailMatch: "not running",
		},
		{
			// An unreadable configuration is not evidence of one.
			name:        "probe error never scores",
			liveness:    running,
			filter:      darwin.ContentFilterState{Installed: true, Enabled: true, Error: "permission denied"},
			wantActive:  false,
			detailMatch: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active, detail := networkExtensionState(tt.liveness, tt.filter)
			if active != tt.wantActive {
				t.Errorf("active = %v, want %v (detail: %s)", active, tt.wantActive, detail)
			}
			if !strings.Contains(detail, tt.detailMatch) {
				t.Errorf("detail = %q, want it to contain %q", detail, tt.detailMatch)
			}
			caps := darwinCaps(tt.liveness, tt.filter)
			if got := caps["network_extension"].(bool); got != tt.wantActive {
				t.Errorf("caps[network_extension] = %v, want %v", got, tt.wantActive)
			}
		})
	}
}
