package provider

import (
	"context"

	"github.com/diffsec/agentmon/internal/httpretry"
)

// The bounded-retry client and circuit breaker used to live here. They moved
// to internal/httpretry when content inspection grew its own HTTP provider
// (internal/inspect/provider), because two copies of retry, jitter and
// breaker accounting would have drifted -- and the subtle part, not counting
// caller cancellation as provider ill-health, is exactly what a second copy
// gets wrong.
//
// These aliases keep this package's existing call sites and tests unchanged.
type (
	retryConfig          = httpretry.Config
	retryClient          = httpretry.Client
	circuitBreakerConfig = httpretry.BreakerConfig
	circuitBreaker       = httpretry.Breaker
)

var (
	errMaxAttempts = httpretry.ErrMaxAttempts
	errBreakerOpen = httpretry.ErrBreakerOpen
)

func newRetryClient(cfg retryConfig) *retryClient { return httpretry.New(cfg) }

func newCircuitBreaker(cfg circuitBreakerConfig) *circuitBreaker { return httpretry.NewBreaker(cfg) }

func callWithBreaker(b *circuitBreaker, callerCtx context.Context, neutralIfErr func(error) bool, fn func() error) error {
	return httpretry.CallWithBreaker(b, callerCtx, neutralIfErr, fn)
}
