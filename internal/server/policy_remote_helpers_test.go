package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/diffsec/agentmon/internal/policy"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "file.pem")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// remoteSourceOf unwraps a CachingSource to reach the RemoteSource inside.
func remoteSourceOf(t *testing.T, src policy.Source) *policy.RemoteSource {
	t.Helper()
	if rs, ok := src.(*policy.RemoteSource); ok {
		return rs
	}
	t.Fatalf("source is %T, not a *policy.RemoteSource", src)
	return nil
}
