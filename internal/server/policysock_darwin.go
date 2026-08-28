//go:build darwin

package server

import (
	"context"
	"log/slog"

	"github.com/diffsec/agentmon/internal/config"
	"github.com/diffsec/agentmon/internal/platform/darwin"
	"github.com/diffsec/agentmon/internal/platform/darwin/policysock"
	"github.com/diffsec/agentmon/internal/policy"
)

// startPolicySocket creates and starts the policy socket server for macOS
// system extension IPC. It sets the policySockCancel and policySockDone
// fields on the Server so the socket is shut down when the server stops.
func (s *Server) startPolicySocket(cfg *config.Config, engine *policy.Engine) {
	sockPath := cfg.PolicySocket.Path
	if sockPath == "" {
		return
	}

	// The directory is created by policysock.prepareSocketPath, which also
	// checks its ownership and mode. Creating it here with 0755 first would
	// have defeated that check on the very first run.
	//
	// A custom path cannot be discovered by the system extension: it runs as
	// root, starts independently, and has no channel to the daemon that does
	// not itself run over this socket. Silently accepting one would mean macOS
	// enforcement quietly stops, which is exactly the class of failure this
	// codebase keeps removing.
	if !config.PolicySocketPathIsDefault(sockPath) {
		slog.Warn("policy_socket.path is not the default; the system extension looks only at the default path, so macOS file, exec and network enforcement will not engage",
			"configured", sockPath)
	}

	// Build the policy adapter that bridges policy.Engine to the policysock
	// handler interface. Pass nil for session resolver for now; the session
	// tracker within the policysock server handles PID-to-session mapping
	// via register_session messages from the system extension.
	tracker := policysock.NewSessionTracker()
	adapter := policysock.NewPolicyAdapter(engine, tracker)

	// Create command resolver and event handler.
	cmdResolver := policysock.NewCommandResolver()
	eventHandler := policysock.NewESFEventHandler(s.store, cmdResolver, tracker)

	psrv := policysock.NewServer(sockPath, adapter)
	psrv.SetTeamID(cfg.PolicySocket.TeamID)
	psrv.SetExecHandler(adapter)
	psrv.SetSnapshotBuilder(adapter)
	psrv.SetSessionRegistrar(tracker)
	psrv.SetEventHandler(eventHandler)

	// Register the extension-presence probe so CheckSysExtLiveness can tell a
	// working extension from a crash-looping one. Without this, liveness is
	// decided by the launchd service state alone, which reports a process
	// denied Full Disk Access as "running" for part of every respawn cycle --
	// and `agentmon wrap` gates on that, so it would intermittently launch an
	// agent believing ESF was enforcing when it was not.
	darwin.SetExtensionPresenceProbe(psrv.ExtensionConnected)

	// Store resolver and tracker so exec handler can register PIDs and sessions.
	s.cmdResolver = cmdResolver
	s.sessionTracker = tracker

	ctx, cancel := context.WithCancel(context.Background())
	s.policySockCancel = cancel
	s.policySockDone = make(chan struct{})

	go func() {
		defer close(s.policySockDone)
		if err := psrv.Run(ctx); err != nil {
			slog.Error("policy socket server exited with error", "error", err)
		}
	}()

	// Wait for the server to become ready (or fail).
	<-psrv.Ready()
	if err := psrv.StartErr(); err != nil {
		slog.Warn("policy socket server failed to start", "error", err)
		cancel()
		<-s.policySockDone
		s.policySockCancel = nil
		s.policySockDone = nil
		return
	}

	slog.Info("policy socket server started", "path", sockPath)

	// Tell the extension the socket is back.
	//
	// Without this, a restarted server is invisible to a running extension.
	// The event stream is write-only -- PolicySocketClient has no read loop,
	// and streamConnected only flips to false inside writeEvent when a write
	// fails -- so when the server goes away while no events are flowing (no
	// active session), the extension keeps a dead fd, never fails a write,
	// and therefore never calls scheduleReconnect. Measured: 45 seconds with
	// zero reconnect attempts against a 30-second maximum backoff, on a
	// healthy extension, with `lsof` showing no client connection at all.
	//
	// The Swift side observes this notification and forces
	// doConnectEventStream, which closes any stale fd first, so it recovers
	// the case above rather than merely racing it. NotifyPolicyUpdated had no
	// callers anywhere before this.
	darwin.NotifyPolicyUpdated()
}
