package api

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"

	"github.com/diffsec/agentmon/internal/auth"
	"github.com/diffsec/agentmon/internal/config"
)

// TestGRPCAuth_LocalMode: the gRPC listener needs the local key too, or an
// agent could use it instead of the HTTP API.
func TestGRPCAuth_LocalMode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Type = "local"
	app := &App{cfg: cfg, apiKeyAuth: auth.NewLocalKeyAuth("local-key", "")}

	if err := grpcAuth(app, context.Background()); err == nil {
		t.Error("a call with no metadata was allowed")
	}
	bad := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "guess"))
	if err := grpcAuth(app, bad); err == nil {
		t.Error("a call with a wrong key was allowed")
	}
	good := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", "local-key"))
	if err := grpcAuth(app, good); err != nil {
		t.Errorf("a call with the local key was refused: %v", err)
	}
}
