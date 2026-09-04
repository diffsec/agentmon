package policyserve

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/diffsec/agentmon/internal/policy"
)

// Request headers carrying the agent's decision context. They mirror
// decisionctx.DecisionContext, which the agent already resolves for Watchtower.
const (
	HeaderHostname = "X-Agentmon-Hostname"
	HeaderUser     = "X-Agentmon-User"
	HeaderTags     = "X-Agentmon-Tags"
	HeaderTenant   = "X-Agentmon-Tenant"
)

// MaxWait caps the long-poll hold. A request held indefinitely survives a
// silently dropped connection as a goroutine on the server and a stalled poll
// on the agent, and neither end finds out.
const MaxWait = 5 * time.Minute

// DefaultWait applies when a request asks to wait without saying how long.
const DefaultWait = 30 * time.Second

// Server answers policy fetches. It is the counterpart of policy.RemoteSource.
type Server struct {
	store  *DirStore
	logger *slog.Logger
}

// NewServer wires a store to the HTTP handlers.
func NewServer(store *DirStore, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: store, logger: logger}
}

// Handler returns the mux serving the policy API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy", s.handlePolicy)
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

// selectorFrom reads the agent's identity from headers, falling back to query
// parameters so a fetch can be reproduced with curl.
//
// None of this is authenticated. It selects which policy an agent is offered,
// never what that agent is allowed to do: an agent that lies about its
// hostname gets a different signed document, and every rule in it is still one
// the operator signed. Authentication belongs at the transport (mTLS), and
// until it is there a binding is a convenience, not a boundary.
func selectorFrom(r *http.Request) Selector {
	q := r.URL.Query()
	pick := func(header, param string) string {
		if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
			return v
		}
		return strings.TrimSpace(q.Get(param))
	}
	sel := Selector{
		Tenant:   pick(HeaderTenant, "tenant"),
		Hostname: pick(HeaderHostname, "hostname"),
		User:     pick(HeaderUser, "user"),
	}
	raw := pick(HeaderTags, "tags")
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			sel.Tags = append(sel.Tags, t)
		}
	}
	return sel
}

// parseWait reads the long-poll duration. An unparseable value is treated as
// no wait rather than as an error: the agent then polls on its ticker, which
// is slower than it asked for but still correct.
func parseWait(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0
	}
	if d <= 0 {
		return 0
	}
	if d > MaxWait {
		return MaxWait
	}
	return d
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sel := selectorFrom(r)
	bundle, binding, ok := s.store.Lookup(sel)
	if !ok {
		// No binding is not an empty policy. Answering 404 leaves the agent
		// enforcing what it already has; answering 200 with nothing would
		// disable enforcement on every agent that fell out of a binding.
		s.logger.Warn("policy serve: no binding matches",
			"tenant", sel.Tenant, "hostname", sel.Hostname, "user", sel.User, "tags", sel.Tags)
		http.Error(w, "no policy bound to this agent", http.StatusNotFound)
		return
	}

	inm := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if inm != "" && inm == bundle.Version {
		if wait := parseWait(r.URL.Query().Get("wait")); wait > 0 {
			bundle, ok = s.await(r, sel, wait)
			if !ok {
				w.Header().Set("ETag", inm)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		} else {
			w.Header().Set("ETag", bundle.Version)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	s.write(w, r, bundle, binding)
}

// await blocks until the store reloads into a bundle this agent has not seen,
// or the deadline passes. It re-reads the channel each round because a reload
// that changed some other tenant's policy leaves this one unchanged.
func (s *Server) await(r *http.Request, sel Selector, wait time.Duration) (*policy.Bundle, bool) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	inm := strings.TrimSpace(r.Header.Get("If-None-Match"))
	for {
		changed := s.store.Changed()
		select {
		case <-r.Context().Done():
			return nil, false
		case <-deadline.C:
			return nil, false
		case <-changed:
			bundle, _, ok := s.store.Lookup(sel)
			if !ok {
				// The reload removed this agent's binding. Reporting it as
				// unchanged keeps the agent on its current policy, which is
				// the same answer 404 would produce and costs no round trip.
				return nil, false
			}
			if bundle.Version != inm {
				return bundle, true
			}
		}
	}
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, bundle *policy.Bundle, binding string) {
	h := w.Header()
	h.Set("Content-Type", "application/yaml")
	h.Set("ETag", bundle.Version)
	// The signature travels beside the document, not wrapped around it, so the
	// body is byte-for-byte what was signed. Re-encoding a document out of a
	// JSON envelope invalidates a signature that was fine.
	if len(bundle.Signature) > 0 {
		h.Set(policy.SignatureHeader, string(bundle.Signature))
	}
	// A cached policy is a stale policy. The ETag is what makes a repeat fetch
	// cheap; a proxy answering from its own cache is what makes a push slow.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Agentmon-Policy-Binding", binding)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(bundle.Data); err != nil {
		s.logger.Warn("policy serve: write failed", "binding", binding, "error", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	policies, bindings := s.store.Stats()
	resp := map[string]any{"status": "ok", "policies": policies, "bindings": bindings}
	status := http.StatusOK
	if err := s.store.LoadErr(); err != nil {
		// Degraded, not down: the previously loaded bundles are still served.
		// Reporting ok would hide a policy the operator believes is live.
		status = http.StatusServiceUnavailable
		resp["status"] = "degraded"
		resp["error"] = err.Error()
		s.logger.Warn("policy serve: serving a stale set after a failed reload", "error", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}
