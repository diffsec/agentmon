// Package httpretry provides a bounded-retry HTTP client and a circuit
// breaker for calling external providers.
//
// It was lifted out of internal/pkgcheck/provider when content inspection
// grew its own HTTP provider. The behaviour is unchanged; only the names are
// exported. Two independent copies of retry, jitter and breaker accounting
// would have drifted, and the subtle part -- not counting caller cancellation
// as provider ill-health, see IsNeutralForBreaker -- is exactly the kind of
// detail a second copy gets wrong.
package httpretry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Config configures the bounded-retry HTTP client.
type Config struct {
	MaxAttempts       int
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
	RespectRetryAfter bool
	Transport         http.RoundTripper // optional, defaults to http.DefaultTransport
}

// Client wraps http.Client with bounded retries on 429/5xx and
// optional Retry-After header handling.
type Client struct {
	cfg    Config
	client *http.Client
}

// New creates a Client with sane defaults if zero values are passed.
func New(cfg Config) *Client {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Second
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Client{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
	}
}

// Do executes the request with bounded retries on 429/5xx.
// The request body, if any, must be replayable — callers should pass a
// *bytes.Reader or similar that can be re-read.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	var lastErr error
	cancelled := false
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := c.client.Do(req)
		if err != nil {
			// If the failure is due to context cancellation, treat it as
			// an abort regardless of which attempt we are on — never wrap
			// it as max-attempts exhaustion.
			if ctxErr := req.Context().Err(); ctxErr != nil {
				lastErr = ctxErr
				cancelled = true
				break
			}
			lastErr = err
			if attempt == c.cfg.MaxAttempts {
				break
			}
			if !c.sleep(attempt, nil, req) {
				lastErr = req.Context().Err()
				cancelled = true
				break
			}
			continue
		}

		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Retryable status — drain body and try again.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("http status %d", resp.StatusCode)
		if attempt == c.cfg.MaxAttempts {
			break
		}
		if !c.sleep(attempt, resp, req) {
			lastErr = req.Context().Err()
			cancelled = true
			break
		}
	}

	if cancelled {
		// Don't classify a cancellation as "max attempts exceeded" — callers
		// using errors.Is(err, ErrMaxAttempts) should be able to distinguish.
		return nil, fmt.Errorf("httpretry: aborted: %w", lastErr)
	}
	// Even if the loop exited via the final-attempt break path, the context
	// may have been cancelled in the meantime (e.g., the final attempt's
	// request returned a 5xx, then ctx was cancelled before we hit this
	// return). Surface that as a cancellation rather than max-attempts.
	if ctxErr := req.Context().Err(); ctxErr != nil {
		return nil, fmt.Errorf("httpretry: aborted: %w", ctxErr)
	}
	return nil, fmt.Errorf("httpretry: gave up after %d attempts: %w", c.cfg.MaxAttempts, errors.Join(ErrMaxAttempts, lastErr))
}

// sleep applies Retry-After (when configured and present) or exponential
// backoff with jitter. Honors context cancellation.
func (c *Client) sleep(attempt int, resp *http.Response, req *http.Request) bool {
	wait := c.backoff(attempt)
	if c.cfg.RespectRetryAfter && resp != nil {
		if h := resp.Header.Get("Retry-After"); h != "" {
			if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
	}
	if wait > c.cfg.MaxBackoff {
		wait = c.cfg.MaxBackoff
	}

	select {
	case <-time.After(wait):
		return true
	case <-req.Context().Done():
		return false
	}
}

// backoff returns exponential-with-jitter backoff for the given attempt.
func (c *Client) backoff(attempt int) time.Duration {
	exp := time.Duration(1<<uint(attempt-1)) * c.cfg.BaseBackoff
	if exp <= 0 || exp > c.cfg.MaxBackoff {
		exp = c.cfg.MaxBackoff
	}
	// Full jitter: random in [0, exp].
	jitter := time.Duration(rand.Int63n(int64(exp) + 1))
	return jitter
}

// ErrMaxAttempts is exposed for tests that want to assert "gave up".
var ErrMaxAttempts = errors.New("max retry attempts exceeded")

// BreakerConfig controls breaker behavior.
type BreakerConfig struct {
	Threshold  int           // consecutive failures before opening
	Window     time.Duration // window in which Threshold failures must occur
	OpenPeriod time.Duration // how long the breaker stays open
}

// Breaker tracks consecutive provider failures and short-circuits
// while open. Safe for concurrent use.
//
// Use CallWithBreaker as the default invocation site for provider HTTP work;
// the Socket and Snyk providers introduced later wrap their CheckBatch calls
// with it. Each provider holds its own breaker instance so that failures of
// one provider do not isolate the other.
type Breaker struct {
	cfg BreakerConfig

	mu             sync.Mutex
	failures       int
	firstFailureAt time.Time
	openedAt       time.Time
}

func NewBreaker(cfg BreakerConfig) *Breaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 3
	}
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.OpenPeriod <= 0 {
		cfg.OpenPeriod = 60 * time.Second
	}
	return &Breaker{cfg: cfg}
}

// Allow reports whether a call may proceed.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.openedAt.IsZero() {
		return true
	}
	if time.Since(b.openedAt) >= b.cfg.OpenPeriod {
		// Re-close.
		b.openedAt = time.Time{}
		b.failures = 0
		return true
	}
	return false
}

// RecordSuccess resets the failure counter.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.firstFailureAt = time.Time{}
}

// RecordFailure increments the failure counter and opens the breaker if the
// threshold is crossed within the window.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.failures == 0 || now.Sub(b.firstFailureAt) > b.cfg.Window {
		b.failures = 1
		b.firstFailureAt = now
	} else {
		b.failures++
	}

	if b.failures >= b.cfg.Threshold {
		b.openedAt = now
	}
}

// ErrBreakerOpen is returned by CallWithBreaker when the breaker is open.
// Callers can detect short-circuited calls via errors.Is(err, ErrBreakerOpen).
var ErrBreakerOpen = errors.New("circuit breaker open")

// CallWithBreaker runs fn under the protection of a circuit breaker.
//
// If the breaker is open, fn is not invoked and ErrBreakerOpen is returned.
// Otherwise fn is invoked, and its outcome is recorded on the breaker:
// errors trip a RecordFailure, success records a RecordSuccess.
//
// Provider implementations use this as their single invocation site for
// CheckBatch's outbound HTTP work, so a sustained-failure provider stops
// taking the network round-trip cost on every install.
//
// callerCtx must be the original parent context — NOT a derived
// context with the provider's own per-request timeout. We use it to
// distinguish caller-driven cancellation/deadline (neutral, no failure
// recorded) from a provider-own timeout firing (real provider-health
// signal, recorded as failure). When callerCtx is nil the function falls
// back to the previous behaviour where any context.Canceled/DeadlineExceeded
// is treated as neutral.
//
// neutralIfErr (optional, may be nil) lets callers mark domain-specific
// errors as neutral for breaker accounting — e.g. authentication errors
// where N concurrent workers all see a 401 and would otherwise open the
// breaker before the auth error reaches the caller.
func CallWithBreaker(b *Breaker, callerCtx context.Context, neutralIfErr func(error) bool, fn func() error) error {
	if b == nil {
		return fn()
	}
	if !b.Allow() {
		return ErrBreakerOpen
	}
	if err := fn(); err != nil {
		if IsNeutralForBreaker(callerCtx, err) {
			return err
		}
		if neutralIfErr != nil && neutralIfErr(err) {
			return err
		}
		b.RecordFailure()
		return err
	}
	b.RecordSuccess()
	return nil
}

// IsNeutralForBreaker reports whether err should be excluded from breaker
// health accounting. Caller-driven cancellation/deadline (visible on
// callerCtx itself) is neutral; provider-own timeouts are not.
func IsNeutralForBreaker(callerCtx context.Context, err error) bool {
	if callerCtx != nil && callerCtx.Err() != nil {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	if callerCtx == nil {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	return false
}
