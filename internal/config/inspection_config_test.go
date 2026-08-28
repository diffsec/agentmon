package config

import (
	"os"
	"testing"
	"time"
)

func TestRepoConfigYMLParsesInspection(t *testing.T) {
	data, err := os.ReadFile("../../config.yml")
	if err != nil {
		t.Skipf("config.yml not readable: %v", err)
	}
	tmp := t.TempDir() + "/config.yml"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(tmp)
	if err != nil {
		t.Fatalf("the shipped config.yml no longer loads: %v", err)
	}
	if cfg.Inspection.ProviderTimeout != 10*time.Second {
		t.Errorf("provider_timeout = %v, want 10s", cfg.Inspection.ProviderTimeout)
	}
	rp, ok := cfg.Inspection.Providers["regex"]
	if !ok {
		t.Fatal("the regex provider block did not parse")
	}
	if !rp.Enabled || rp.Type != "regex" {
		t.Errorf("regex provider = %+v", rp)
	}
	if cfg.Inspection.Enabled {
		t.Error("inspection is enabled by default in the shipped config; it must be opt-in")
	}
	if cfg.Inspection.Privacy.AllowRemote {
		t.Error("allow_remote defaults to true in the shipped config; content would leave the machine")
	}
}
