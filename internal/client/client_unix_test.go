package client

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestClient_UnixSocketHealth(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets not supported on Windows")
	}
	// Not t.TempDir(): it derives the directory name from the test name, which
	// here produced a 103-byte socket path -- one byte under the limit. macOS
	// sockaddr_un.sun_path is 104 bytes *including* the NUL terminator, so 103
	// characters is the true maximum, and renaming agentsh.sock -> agentmon.sock
	// was enough to tip it over into EINVAL. Use a short directory instead so the
	// path length does not depend on the length of the test's own name.
	dir, err := os.MkdirTemp("", "amc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agentmon.sock")

	ln, err := net.Listen("unix", sock)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("unix listen not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close(); _ = os.Remove(sock) })

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	c := New("unix://"+sock, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.doJSON(ctx, http.MethodGet, "/health", nil, nil, nil); err != nil {
		t.Fatalf("health request failed: %v", err)
	}
}
