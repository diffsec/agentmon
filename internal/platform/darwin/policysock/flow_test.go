//go:build darwin

package policysock

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"
)

// echoFlowHandler accepts flows to port 443 and echoes their bytes, and
// refuses every other flow.
type echoFlowHandler struct{ got chan FlowOpen }

func (h echoFlowHandler) HandleFlow(conn net.Conn, f FlowOpen, accepted func() error, refused func(string)) {
	defer conn.Close()
	h.got <- f
	if f.Port != 443 {
		refused("port not allowed")
		return
	}
	if accepted() != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

func startFlowServer(t *testing.T, h FlowHandler) string {
	t.Helper()
	sockPath := testSockPath(t)
	srv := NewServer(sockPath, &testPolicyHandler{})
	if h != nil {
		srv.SetFlowHandler(h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Run(ctx)
	<-srv.Ready()
	if err := srv.StartErr(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	return sockPath
}

// openFlow sends a flow_open request, as the extension does, with no newline
// after it, and returns the connection and the response.
func openFlow(t *testing.T, sockPath string, req map[string]any) (net.Conn, *bufio.Reader, PolicyResponse) {
	t.Helper()
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	b, _ := json.Marshal(req)
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	var resp PolicyResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("response %q: %v", line, err)
	}
	return conn, r, resp
}

func TestFlowOpen_AcceptedFlowCarriesBytes(t *testing.T) {
	h := echoFlowHandler{got: make(chan FlowOpen, 1)}
	sockPath := startFlowServer(t, h)
	conn, r, resp := openFlow(t, sockPath, map[string]any{
		"type": "flow_open", "session_id": "s1", "pid": 42,
		"host": "93.184.216.34", "port": 443, "domain": "example.com",
	})
	if !resp.Allow {
		t.Fatalf("flow refused: %s", resp.Message)
	}
	f := <-h.got
	if f.SessionID != "s1" || f.PID != 42 || f.Host != "93.184.216.34" || f.Port != 443 || f.Hostname != "example.com" {
		t.Fatalf("handler got %+v", f)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestFlowOpen_RefusedFlowGetsTheReason(t *testing.T) {
	sockPath := startFlowServer(t, echoFlowHandler{got: make(chan FlowOpen, 1)})
	_, _, resp := openFlow(t, sockPath, map[string]any{
		"type": "flow_open", "session_id": "s1", "host": "10.0.0.1", "port": 22,
	})
	if resp.Allow || resp.Message != "port not allowed" {
		t.Fatalf("response = %+v, want a refusal with the handler's reason", resp)
	}
}

func TestFlowOpen_NoHandlerOrBadRequestIsRefused(t *testing.T) {
	sockPath := startFlowServer(t, nil)
	_, _, resp := openFlow(t, sockPath, map[string]any{
		"type": "flow_open", "session_id": "s1", "host": "10.0.0.1", "port": 443,
	})
	if resp.Allow {
		t.Fatal("a flow was allowed with no flow handler")
	}

	sockPath = startFlowServer(t, echoFlowHandler{got: make(chan FlowOpen, 1)})
	for _, req := range []map[string]any{
		{"type": "flow_open", "host": "10.0.0.1", "port": 443},
		{"type": "flow_open", "session_id": "s1", "port": 443},
		{"type": "flow_open", "session_id": "s1", "host": "10.0.0.1", "port": 70000},
	} {
		if _, _, resp := openFlow(t, sockPath, req); resp.Allow {
			t.Fatalf("incomplete request %v was allowed", req)
		}
	}
}
