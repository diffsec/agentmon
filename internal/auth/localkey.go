package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LocalKeyFile is the name of the file that holds the key for auth.type
// local, in the daemon's user data directory.
//
// The key keeps an agent from calling the daemon's API on localhost, where it
// could create a session with a policy of its choosing. The daemon and the
// agentmon CLI read the file. On macOS the system extension refuses session
// processes any access to the directory that holds it, and refuses them an
// exec of the agentmon CLI.
const LocalKeyFile = "local-api.key"

// localKeyBytes is the key length before hex encoding.
const localKeyBytes = 32

// EnsureLocalKey returns the key stored at path, and writes a new random key
// there first if the file does not exist. The file is created with mode 0600,
// and an existing file is tightened to 0600.
func EnsureLocalKey(path string) (string, error) {
	key, err := ReadLocalKey(path)
	if err != nil {
		return "", err
	}
	if key != "" {
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("tighten local api key file %s: %w", path, err)
		}
		return key, nil
	}

	raw := make([]byte, localKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate local api key: %w", err)
	}
	key = hex.EncodeToString(raw)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create directory for local api key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Another process created it first. Use its key.
		return EnsureLocalKey(path)
	}
	if err != nil {
		return "", fmt.Errorf("create local api key file %s: %w", path, err)
	}
	if _, err := f.WriteString(key + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write local api key file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write local api key file %s: %w", path, err)
	}
	return key, nil
}

// ReadLocalKey returns the key stored at path, or "" when the file does not
// exist or is empty.
func ReadLocalKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read local api key file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// NewLocalKeyAuth returns an APIKeyAuth that accepts one key, with the admin
// role.
func NewLocalKeyAuth(key, headerName string) *APIKeyAuth {
	if strings.TrimSpace(headerName) == "" {
		headerName = "X-API-Key"
	}
	return &APIKeyAuth{headerName: headerName, keys: map[string]string{key: "admin"}}
}
