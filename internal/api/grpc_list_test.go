package api

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"

	"github.com/diffsec/agentmon/internal/client"
	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/session"
)

// TestGRPC_ListSessionsRoundTrip runs a real gRPC server and client.
//
// ListSessions returned a JSON array. A structpb.Struct holds only an object,
// so every call failed with "marshal response". The client also discarded
// the decode error, so a wrong shape read as an empty list.
func TestGRPC_ListSessionsRoundTrip(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "none"
	mgr := session.NewManager(5)
	for _, ws := range []string{t.TempDir(), t.TempDir()} {
		if _, err := mgr.Create(ws, "default"); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{cfg: cfg, sessions: mgr}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	RegisterGRPC(srv, app)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	c, err := client.NewGRPC(lis.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListSessions returned %d sessions, want 2", len(got))
	}
	for _, s := range got {
		if s.ID == "" || s.Policy != "default" {
			t.Errorf("session decoded as %+v", s)
		}
	}

	approvals, err := c.ListApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(approvals) != 0 {
		t.Errorf("ListApprovals returned %d, want 0", len(approvals))
	}
}
