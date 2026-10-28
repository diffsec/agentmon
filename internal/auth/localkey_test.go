package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureLocalKey_CreatesPrivateKeyAndReusesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", LocalKeyFile)

	key, err := EnsureLocalKey(path)
	if err != nil {
		t.Fatalf("EnsureLocalKey: %v", err)
	}
	if len(key) != 2*localKeyBytes {
		t.Errorf("key length = %d, want %d", len(key), 2*localKeyBytes)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600: another account could read the key", perm)
	}

	again, err := EnsureLocalKey(path)
	if err != nil {
		t.Fatalf("EnsureLocalKey second call: %v", err)
	}
	if again != key {
		t.Error("a second call made a new key, so a running CLI would hold a stale one")
	}
	if got, _ := ReadLocalKey(path); got != key {
		t.Errorf("ReadLocalKey = %q, want the stored key", got)
	}
}

func TestEnsureLocalKey_TightensALooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), LocalKeyFile)
	if err := os.WriteFile(path, []byte("abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	key, err := EnsureLocalKey(path)
	if err != nil {
		t.Fatalf("EnsureLocalKey: %v", err)
	}
	if key != "abc" {
		t.Errorf("key = %q, want the existing key", key)
	}
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", perm)
	}
}

func TestReadLocalKey_MissingFileIsEmpty(t *testing.T) {
	key, err := ReadLocalKey(filepath.Join(t.TempDir(), LocalKeyFile))
	if err != nil || key != "" {
		t.Errorf("ReadLocalKey = %q, %v; want \"\", nil", key, err)
	}
}

func TestNewLocalKeyAuth_AcceptsOnlyItsKey(t *testing.T) {
	a := NewLocalKeyAuth("k", "")
	if !a.IsAllowed("k") || a.RoleForKey("k") != "admin" {
		t.Error("the local key must be allowed with the admin role")
	}
	if a.IsAllowed("") || a.IsAllowed("other") {
		t.Error("only the local key may be allowed")
	}
	if a.HeaderName() != "X-API-Key" {
		t.Errorf("header = %q, want X-API-Key", a.HeaderName())
	}
}
