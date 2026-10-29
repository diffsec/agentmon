//go:build darwin

package policysock

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
)

// FlowOpen is one TCP flow that the system extension's transparent proxy
// captured from a session process.
type FlowOpen struct {
	SessionID string
	PID       int32
	// Host is the remote endpoint: an address, or a name when the app
	// connected by name.
	Host string
	Port int
	// Hostname is the name that the app asked for, if the system knows it.
	Hostname string
}

// FlowHandler decides a flow and forwards its bytes. It calls accepted once
// the upstream connection is open, or refused if the flow is denied or the
// upstream cannot be reached, and it closes conn when the flow ends.
type FlowHandler interface {
	HandleFlow(conn net.Conn, flow FlowOpen, accepted func() error, refused func(reason string))
}

// handleFlow runs a flow_open connection. The extension waits for one
// response line. After {"allow":true}, the connection is the flow, so the
// response is written only once the upstream connection is open.
//
// Only the system extension reaches this. Run classified the peer, and the
// extension refuses a session process a connection to the daemon's
// directory (handleAuthUIPCConnect), so an agent cannot open a flow that
// claims another session.
func (s *Server) handleFlow(conn net.Conn, dec *json.Decoder, req *PolicyRequest) {
	s.mu.Lock()
	h := s.flowHandler
	s.mu.Unlock()

	enc := json.NewEncoder(conn)
	refused := func(reason string) {
		_ = enc.Encode(PolicyResponse{Allow: false, Message: reason})
	}
	if h == nil {
		refused("the daemon has no flow handler")
		return
	}
	if req.SessionID == "" || req.Host == "" || req.Port <= 0 || req.Port > 65535 {
		refused("flow_open needs session_id, host and port")
		return
	}

	// The decoder can hold bytes past the request. The extension sends the
	// request with no newline after it and sends no flow bytes before the
	// response, so this is normally empty. Whitespace between JSON values is
	// not flow data, so it is dropped. Any other byte belongs to the flow.
	var flowConn net.Conn = conn
	if b, _ := io.ReadAll(dec.Buffered()); len(bytes.TrimLeft(b, " \t\r\n")) > 0 {
		rest := bytes.TrimLeft(b, " \t\r\n")
		flowConn = &bufferedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(rest), conn)}
	}

	h.HandleFlow(flowConn, FlowOpen{
		SessionID: req.SessionID,
		PID:       req.PID,
		Host:      req.Host,
		Port:      req.Port,
		Hostname:  req.Domain,
	}, func() error {
		return enc.Encode(PolicyResponse{Allow: true})
	}, refused)
}

// bufferedConn reads bytes that the JSON decoder already buffered before the
// rest of the connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite keeps the half-close that the gateway's splice relies on.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
