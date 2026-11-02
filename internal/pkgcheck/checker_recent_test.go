package pkgcheck

import (
	"context"
	"testing"
	"time"
)

// countingResolver resolves every pip install to one package and counts the
// calls, so that a test can see whether Check resolved again.
type countingResolver struct{ calls int }

func (r *countingResolver) Name() string { return "counting" }

func (r *countingResolver) CanResolve(tool string, _ []string) bool { return tool == "pip" }

func (r *countingResolver) Resolve(context.Context, string, []string) (*InstallPlan, error) {
	r.calls++
	return &InstallPlan{
		Tool:      "pip",
		Ecosystem: EcosystemPyPI,
		Direct:    []PackageRef{{Name: "requests", Version: "2.0.0", Direct: true}},
	}, nil
}

func TestCheckReusesRecentVerdict(t *testing.T) {
	res := &countingResolver{}
	c := NewChecker(CheckerConfig{Resolvers: []Resolver{res}})
	clock := time.Unix(1000, 0)
	c.now = func() time.Time { return clock }
	ctx := context.Background()
	dir := t.TempDir()

	if _, err := c.Check(ctx, "pip3", []string{"install", "requests"}, dir); err != nil {
		t.Fatal(err)
	}
	// The same install as macOS ES reports it: a versioned name.
	if _, err := c.Check(ctx, "/opt/homebrew/bin/pip3.15", []string{"install", "requests"}, dir); err != nil {
		t.Fatal(err)
	}
	// The same install as `python3 -m pip`.
	if _, err := c.Check(ctx, "/opt/homebrew/bin/python3", []string{"-m", "pip", "install", "requests"}, dir); err != nil {
		t.Fatal(err)
	}
	if res.calls != 1 {
		t.Fatalf("resolved %d times within recentTTL, want 1", res.calls)
	}

	clock = clock.Add(recentTTL + time.Second)
	if _, err := c.Check(ctx, "pip3", []string{"install", "requests"}, dir); err != nil {
		t.Fatal(err)
	}
	if res.calls != 2 {
		t.Errorf("resolved %d times after recentTTL, want 2", res.calls)
	}
}

func TestUnwrapInstallCommand(t *testing.T) {
	for _, c := range []struct {
		cmd      string
		args     []string
		wantCmd  string
		wantArgs int
	}{
		{"/opt/homebrew/bin/python3", []string{"-m", "pip", "install", "x"}, "pip", 2},
		{"python3.15", []string{"-I", "-m", "pip3", "install", "x"}, "pip", 2},
		{"python3", []string{"script.py", "-m", "pip"}, "python3", 3},
		{"python3", []string{"-m", "venv", "x"}, "python3", 3},
		{"node", []string{"-m", "pip"}, "node", 2},
	} {
		cmd, args := UnwrapInstallCommand(c.cmd, c.args)
		if cmd != c.wantCmd || len(args) != c.wantArgs {
			t.Errorf("UnwrapInstallCommand(%s %v) = %s %v", c.cmd, c.args, cmd, args)
		}
	}
	if intent := ClassifyInstallCommand("/opt/homebrew/bin/pip3.15", []string{"install", "x"}, ""); intent == nil || intent.Tool != "pip" {
		t.Errorf("pip3.15 install x: intent = %+v, want a pip install", intent)
	}
}
