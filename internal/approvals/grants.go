package approvals

import (
	"context"
	"fmt"
	"time"
)

// A grant is a person's answer to one request, kept for a short time.
//
// The macOS system extension cannot hold a file or exec event while a person
// reads a dialog, because the kernel answers for it after a few seconds. So
// the extension denies the operation and asks the daemon for an approval. If
// the person approves, the daemon keeps a grant, and the agent's retry within
// the grant period succeeds.
//
// The same store also stops repeated dialogs. A client that connects to a
// host with four addresses opens four flows, and each flow asked for its own
// approval. Requests for the same session, kind, target and operation now
// share one dialog and one answer.

// grantKey identifies the access that a request asks for.
type grantKey struct {
	sessionID string
	kind      string
	target    string
	operation string
}

func keyFor(req Request) grantKey {
	op, _ := req.Fields["operation"].(string)
	return grantKey{sessionID: req.SessionID, kind: req.Kind, target: req.Target, operation: op}
}

// decision is a person's answer, kept until expires.
type decision struct {
	res     Resolution
	expires time.Time
}

// flight is a request that waits for a person. Requests with the same key
// wait for it instead of opening their own dialog.
type flight struct {
	done chan struct{}
	res  Resolution
	err  error
}

// Grant is an approved access that is still in its grant period.
type Grant struct {
	SessionID string
	Kind      string
	Target    string
	Operation string
	ExpiresAt time.Time
}

// SetGrantTTL turns grants on. A person's answer to a request then applies
// to every identical request for ttl.
func (m *Manager) SetGrantTTL(ttl time.Duration) {
	m.grantMu.Lock()
	defer m.grantMu.Unlock()
	m.grantTTL = ttl
	if m.decided == nil {
		m.decided = make(map[grantKey]*decision)
		m.inflight = make(map[grantKey]*flight)
	}
}

// OnGrantChange sets a function that runs when a grant starts or ends. The
// macOS daemon uses it to send the system extension a new policy snapshot.
func (m *Manager) OnGrantChange(fn func(sessionID string)) {
	m.grantMu.Lock()
	defer m.grantMu.Unlock()
	m.onGrantChange = fn
}

// Ask starts an approval for req and returns at once. If an identical
// request is waiting, or a person answered one in the grant period, it opens
// no new dialog.
func (m *Manager) Ask(req Request) {
	go func() { _, _ = m.RequestApproval(context.Background(), req) }()
}

// Granted reports whether a person approved this access in the grant period.
func (m *Manager) Granted(sessionID, kind, target, operation string) bool {
	if m == nil {
		return false
	}
	m.grantMu.Lock()
	defer m.grantMu.Unlock()
	d, ok := m.decided[grantKey{sessionID, kind, target, operation}]
	return ok && d.res.Approved && time.Now().Before(d.expires)
}

// Grants returns the session's approved accesses that are still in their
// grant period.
func (m *Manager) Grants(sessionID string) []Grant {
	if m == nil {
		return nil
	}
	m.grantMu.Lock()
	defer m.grantMu.Unlock()
	now := time.Now()
	var out []Grant
	for k, d := range m.decided {
		if k.sessionID != sessionID || !d.res.Approved || !now.Before(d.expires) {
			continue
		}
		out = append(out, Grant{SessionID: k.sessionID, Kind: k.kind, Target: k.target, Operation: k.operation, ExpiresAt: d.expires})
	}
	return out
}

func (m *Manager) requestOnce(ctx context.Context, req Request) (Resolution, error) {
	key := keyFor(req)

	m.grantMu.Lock()
	if d, ok := m.decided[key]; ok && time.Now().Before(d.expires) {
		m.grantMu.Unlock()
		res := d.res
		res.Reason = fmt.Sprintf("%s (answer reused until %s)", res.Reason, d.expires.UTC().Format(time.RFC3339))
		return res, nil
	}
	if f, ok := m.inflight[key]; ok {
		m.grantMu.Unlock()
		select {
		case <-f.done:
			return f.res, f.err
		case <-ctx.Done():
			return Resolution{Approved: false, Reason: "context canceled", At: time.Now().UTC()}, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	m.inflight[key] = f
	m.grantMu.Unlock()

	f.res, f.err = m.requestApproval(ctx, req)

	m.grantMu.Lock()
	delete(m.inflight, key)
	// Keep only an answer: a timeout, a canceled context or a rate limit
	// returns an error, and the next request asks again.
	var d *decision
	if f.err == nil {
		d = &decision{res: f.res, expires: time.Now().Add(m.grantTTL)}
		m.decided[key] = d
	}
	notify := m.onGrantChange
	ttl := m.grantTTL
	m.grantMu.Unlock()
	close(f.done)

	if d != nil {
		time.AfterFunc(ttl, func() { m.expire(key, d) })
		if d.res.Approved && notify != nil {
			notify(key.sessionID)
		}
	}
	return f.res, f.err
}

// expire removes d if it is still the answer for key.
func (m *Manager) expire(key grantKey, d *decision) {
	m.grantMu.Lock()
	if m.decided[key] != d {
		m.grantMu.Unlock()
		return
	}
	delete(m.decided, key)
	notify := m.onGrantChange
	m.grantMu.Unlock()
	if d.res.Approved && notify != nil {
		notify(key.sessionID)
	}
}
