package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/policy"
	"github.com/diffsec/agentmon/pkg/types"
)

// DefaultInspectMaxBodyBytes caps how much of a request body is buffered for
// inspection.
//
// The agent controls the body, so an unbounded read is a denial-of-service
// surface against the daemon rather than against the upstream. Exceeding the
// cap is treated as a failed inspection, not as a skip: a body too large to
// inspect is uninspected content, and the rule's on_failure decides what
// happens to it -- which is a deny by default.
//
// 8 MiB rather than something tighter because this proxy carries LLM traffic,
// and a request with a long context legitimately runs to several megabytes. A
// cap set below real payload sizes would turn fail_closed into a blanket
// block on ordinary use, and the operator would have no way to tell that from
// a policy that was working.
const DefaultInspectMaxBodyBytes int64 = 8 << 20 // 8 MiB

// InspectConfig is what a session hands the LLM proxy to enable inspection.
type InspectConfig struct {
	// Resolve supplies the engine and inspector per request.
	Resolve InspectContextFunc
	// MaxBodyBytes overrides DefaultInspectMaxBodyBytes. Zero uses it.
	MaxBodyBytes int64
	// MCPArgMaxBytes overrides DefaultMCPArgMaxBytes, the cap on a single
	// MCP tool call's accumulated arguments. Zero uses it.
	MCPArgMaxBytes int
}

// Enabled reports whether inspection should be wired for this session.
func (c InspectConfig) Enabled() bool { return c.Resolve != nil }

// InspectContextFunc supplies the policy engine and its inspector for the
// current request.
//
// It is a function rather than two stored pointers so the engine is resolved
// per request. Proxy.SetPolicyEngine captures an engine at construction, and
// that capture is why the network, transparent-TCP and DNS paths keep
// enforcing the previous policy after a live update (documented at
// internal/api/session_policy.go:47). Inspection does not need a fourth
// instance of that bug.
type InspectContextFunc func() (*policy.Engine, policy.InspectChecker)

// InspectHook runs content inspection over request bodies.
//
// It resolves only decisions that carry an inspection spec. A plain network
// deny is left alone: the proxy, the macOS network filter and the Linux
// netmonitor each enforce network policy on their own path, and a second
// enforcement point here would change behaviour for every deployment that
// does not use inspection at all.
type InspectHook struct {
	resolve InspectContextFunc
	maxBody int64
	logger  *slog.Logger

	// dlp supplies the redaction strategy. Nil falls back to the
	// placeholder, which is safe but destroys the value downstream.
	dlp *DLPProcessor
}

// SetDLP installs the DLP processor whose token store backs reversible
// redaction. Without it, on_violation: redact writes a placeholder.
func (h *InspectHook) SetDLP(dp *DLPProcessor) { h.dlp = dp }

// NewInspectHook returns a hook that inspects request bodies. A zero or
// negative maxBody uses DefaultInspectMaxBodyBytes.
func NewInspectHook(resolve InspectContextFunc, maxBody int64, logger *slog.Logger) *InspectHook {
	if maxBody <= 0 {
		maxBody = DefaultInspectMaxBodyBytes
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &InspectHook{resolve: resolve, maxBody: maxBody, logger: logger}
}

// Name implements Hook.
func (h *InspectHook) Name() string { return "content-inspect" }

// PostHook implements Hook. Response inspection is not wired: a policy
// decision is about what the agent sends, and the response path has its own
// scrubbing in CredsSubHook and the DLP processor.
func (h *InspectHook) PostHook(*http.Response, *RequestContext) error { return nil }

// PreHook implements Hook.
func (h *InspectHook) PreHook(r *http.Request, ctx *RequestContext) error {
	if h.resolve == nil || r == nil {
		return nil
	}
	eng, checker := h.resolve()
	if eng == nil {
		return nil
	}

	host, port := requestDestination(r, ctx)
	dec := eng.CheckNetwork(host, port)
	if dec.Inspect == nil {
		return nil
	}

	body, err := h.readBody(r)
	if err != nil {
		return h.act(inspect.Fail(dec, "", err), r, ctx, host)
	}

	res := inspect.Resolve(r.Context(), checker, dec, inspect.KindProxyBody, string(body),
		inspect.WithRedactor(redactorFor(h.dlp)))
	return h.act(res, r, ctx, host)
}

// readBody buffers the request body up to the cap and restores it so later
// hooks and the transport still see it.
//
// Reading one byte past the cap is how the cap is detected at all: a read of
// exactly maxBody cannot distinguish a body that fits from one that was
// truncated, and treating a truncated body as the whole body would inspect a
// prefix and report the rest clean.
//
// On both failure paths the buffered prefix is spliced back in front of the
// unread remainder rather than replacing it. Handing back only the prefix
// would mean an `on_failure: fail_open` rule forwards a corrupted request --
// silently, and looking exactly like a body the agent sent that way.
func (h *InspectHook) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	original := r.Body
	originalLen := r.ContentLength

	buf, err := io.ReadAll(io.LimitReader(original, h.maxBody+1))
	if err != nil {
		r.Body = readerCloser{Reader: io.MultiReader(bytes.NewReader(buf), original), Closer: original}
		r.ContentLength = originalLen
		return nil, fmt.Errorf("reading request body: %w", err)
	}

	if int64(len(buf)) > h.maxBody {
		r.Body = readerCloser{Reader: io.MultiReader(bytes.NewReader(buf), original), Closer: original}
		r.ContentLength = originalLen
		return nil, fmt.Errorf("request body exceeds the %d byte inspection limit", h.maxBody)
	}

	// The whole body fit, so the exact length is now known -- which also
	// resolves a chunked request's ContentLength of -1.
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	return buf, nil
}

// readerCloser pairs a spliced reader with the original body's Closer, so
// closing the request still releases the underlying connection.
type readerCloser struct {
	io.Reader
	io.Closer
}

// act applies a resolved decision to the request.
func (h *InspectHook) act(res inspect.Result, r *http.Request, ctx *RequestContext, host string) error {
	switch res.Decision.EffectiveDecision {
	case types.DecisionAllow:
		if res.Rewritten {
			h.replaceBody(r, []byte(res.Content))
			h.logger.Info("content inspection redacted a request body",
				"rule", res.Decision.Rule, "host", host, "detail", res.Verdict.Detail,
				"request_id", requestIDOf(ctx), "session_id", sessionIDOf(ctx))
		}
		return nil

	case types.DecisionApprove:
		// A PreHook can abort or proceed; it has no way to gate on a human.
		// Denying with an explicit message beats silently downgrading to
		// allow, and beats a bare 403 that sends the operator looking for a
		// rule that denied.
		//
		// The blocking shape exists elsewhere and is the follow-up:
		// internal/db/proxy/postgres/approvalwait.go runs the approver in a
		// goroutine with its own timeout and maps the outcomes to
		// approval_denied / approval_timeout / cancelled_during_approval.
		h.logger.Warn("content inspection asked for approval, which the proxy path cannot request; denying",
			"rule", res.Decision.Rule, "host", host,
			"request_id", requestIDOf(ctx), "session_id", sessionIDOf(ctx))
		return &HookAbortError{
			StatusCode: http.StatusForbidden,
			Message:    "blocked by content inspection: this rule requires approval, which is not available on the proxy path",
		}

	default:
		reason := res.Verdict.Detail
		if res.Err != nil {
			reason = "inspection could not run"
		}
		h.logger.Warn("content inspection blocked a request",
			"rule", res.Decision.Rule, "host", host, "detail", reason,
			"error", res.Err, "request_id", requestIDOf(ctx), "session_id", sessionIDOf(ctx))
		return &HookAbortError{
			StatusCode: http.StatusForbidden,
			Message:    inspectAbortMessage(res),
		}
	}
}

// inspectAbortMessage is returned to the agent. It names the rule and the
// categories found, and never the matched text: the message is written into
// the agent's own transcript, which is one of the places the content was
// being kept out of.
func inspectAbortMessage(res inspect.Result) string {
	var b strings.Builder
	b.WriteString("blocked by content inspection")
	if res.Decision.Rule != "" {
		b.WriteString(" (rule ")
		b.WriteString(res.Decision.Rule)
		b.WriteString(")")
	}
	switch {
	case res.Err != nil:
		b.WriteString(": inspection could not run")
	case res.Verdict.Detail != "":
		b.WriteString(": ")
		b.WriteString(res.Verdict.Detail)
	}
	return b.String()
}

func (h *InspectHook) replaceBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	// A rewritten body invalidates a fixed Content-Length header the client
	// set, and any Content-Digest over the original bytes.
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.Header.Del("Content-Digest")
	r.Header.Del("Digest")
}

// requestDestination extracts the host and port a request is bound for.
//
// The resolved upstream comes first, because that is the destination a
// network rule is written about. The agent talks to this proxy on 127.0.0.1,
// so r.Host is the proxy's own listen address -- matching on it would mean a
// rule naming api.anthropic.com never fires while looking like it works.
//
// Port falls back to the scheme default, because a network rule listing
// `ports: [443]` must still match a URL written without one.
func requestDestination(r *http.Request, ctx *RequestContext) (string, int) {
	if ctx != nil {
		if u, ok := ctx.Attrs[AttrUpstreamURL].(*url.URL); ok && u != nil && u.Host != "" {
			return splitHostPort(u.Host, u.Scheme)
		}
	}

	host := r.Host
	if r.URL != nil && r.URL.Host != "" {
		host = r.URL.Host
	}

	// Defaults to https when the URL carries no scheme. The LLM proxy fronts
	// TLS endpoints, and defaulting to http would put port 80 on the decision
	// and silently miss a rule listing `ports: [443]`.
	scheme := "https"
	if r.URL != nil && r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}

	return splitHostPort(host, scheme)
}

func splitHostPort(host, scheme string) (string, int) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		if port, convErr := strconv.Atoi(p); convErr == nil {
			return strings.ToLower(h), port
		}
		return strings.ToLower(h), defaultPortForScheme(scheme)
	}
	return strings.ToLower(host), defaultPortForScheme(scheme)
}

func defaultPortForScheme(scheme string) int {
	if strings.EqualFold(scheme, "http") {
		return 80
	}
	return 443
}

func requestIDOf(ctx *RequestContext) string {
	if ctx == nil {
		return ""
	}
	return ctx.RequestID
}

func sessionIDOf(ctx *RequestContext) string {
	if ctx == nil {
		return ""
	}
	return ctx.SessionID
}

// ensure InspectHook satisfies Hook at compile time.
var _ Hook = (*InspectHook)(nil)
