//go:build !linux

package netmonitor

import (
	"errors"

	"github.com/diffsec/agentmon/internal/approvals"
	dbevents "github.com/diffsec/agentmon/internal/db/events"
	"github.com/diffsec/agentmon/internal/session"
)

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine EngineFunc, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*TransparentTCP, int, error) {
	return nil, 0, errors.New("transparent TCP is only supported on Linux")
}
