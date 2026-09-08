package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/diffsec/agentmon/internal/api"
	"github.com/diffsec/agentmon/internal/policy"
)

// policyPoller fetches from a policy server and installs what it gets.
//
// It never touches enforcement itself. A changed document goes to
// App.ReloadPolicy, which swaps the global engine and rebuilds every running
// session's engine from the same document -- the work #45 added, because
// swapping the global engine alone reaches only sessions that follow it.
type policyPoller struct {
	manager *policy.Manager
	// install applies a changed document. It is a function rather than the
	// App itself so the poller's pacing and change detection are testable
	// without standing up a daemon.
	install  func(*policy.Policy) error
	interval time.Duration
	longPoll time.Duration
	logger   *slog.Logger

	last *policy.Policy
}

func newPolicyPoller(m *policy.Manager, install func(*policy.Policy) error, interval, longPoll time.Duration, logger *slog.Logger) *policyPoller {
	if logger == nil {
		logger = slog.Default()
	}
	return &policyPoller{manager: m, install: install, interval: interval, longPoll: longPoll, logger: logger}
}

// installViaApp applies a document through the App, which reaches every running
// session's engine and not only the process-global one.
func installViaApp(appFn func() *api.App) func(*policy.Policy) error {
	return func(doc *policy.Policy) error {
		app := appFn()
		if app == nil {
			// Before the App exists there is nothing to install into; its own
			// first Manager.Get picks this document up.
			return nil
		}
		res, err := app.ReloadPolicy(doc)
		if err != nil {
			return err
		}
		api.LogPolicyReload(res, doc.Name, 0)
		return nil
	}
}

// Run polls until ctx is cancelled.
//
// With long-polling the server holds each request open, so the next fetch
// starts immediately after one that was actually held. A fetch that returned
// well inside the wait means the server ignored the parameter, and the poller
// falls back to the ticker rather than spinning against it.
func (p *policyPoller) Run(ctx context.Context) {
	// Seed from whatever is already loaded so the first poll that returns the
	// same document is not reported as a change. Cached, not Get: Get would
	// fetch, and the document it fetched would then never be reported.
	p.last = p.manager.Cached()
	for {
		started := time.Now()
		p.pollOnce(ctx)

		delay := p.interval
		if p.longPoll > 0 && time.Since(started) >= p.longPoll/2 {
			delay = 0
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (p *policyPoller) pollOnce(ctx context.Context) {
	doc, err := p.manager.ReloadContext(ctx)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return
		}
		// The Manager keeps the policy it has, so enforcement is unchanged.
		// Saying which is what stops "the server is down" reading as "the
		// policy was withdrawn".
		p.logger.Warn("policy poll failed; the previous policy stays in force",
			"source", p.manager.SourceDescription(), "error", err)
		return
	}
	if doc == nil || doc == p.last {
		return
	}
	p.last = doc

	if p.install == nil {
		return
	}
	if err := p.install(doc); err != nil {
		p.logger.Error("policy poll: installing the new policy failed; the previous policy stays in force",
			"error", err)
	}
}
