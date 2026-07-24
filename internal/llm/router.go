package llm

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

const (
	defaultRouterMaxAttempts = 3
	defaultRouterBaseBackoff = 50 * time.Millisecond
	primaryAttemptTimeout    = 10 * time.Second
)

// LLMRouter wraps a primary and fallback LLMBackend. It attempts the primary
// provider (retrying transient errors with exponential backoff + jitter) and
// falls back to the secondary provider if the primary cannot be reached.
type LLMRouter struct {
	primary  LLMBackend
	fallback LLMBackend

	// Retry policy for the primary. Defaulted in NewLLMRouter; tunable in tests.
	maxAttempts int
	baseBackoff time.Duration
}

// NewLLMRouter creates an LLMRouter that tries primary first, then fallback.
func NewLLMRouter(primary, fallback LLMBackend) *LLMRouter {
	return &LLMRouter{
		primary:     primary,
		fallback:    fallback,
		maxAttempts: defaultRouterMaxAttempts,
		baseBackoff: defaultRouterBaseBackoff,
	}
}

// Complete sends a prompt to the primary backend, retrying transient failures
// with exponential backoff and jitter (bounded by maxAttempts and the caller's
// context deadline). If the primary ultimately fails, it falls back to the
// secondary backend and marks metadata["fallback"] = "true".
func (r *LLMRouter) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	resp, err := r.tryPrimary(ctx, p)
	if err != nil {
		resp, err = r.fallback.Complete(ctx, p)
		if err != nil {
			return nil, err
		}
		if resp.Metadata == nil {
			resp.Metadata = make(map[string]string)
		}
		resp.Metadata["fallback"] = "true"
	}
	return resp, nil
}

// tryPrimary invokes the primary with bounded retries. It retries only transient
// errors — context deadline/cancellation are treated as terminal, since retrying
// within the same budget will not help (and would slow the fallback path).
func (r *LLMRouter) tryPrimary(ctx context.Context, p Prompt) (*LLMResponse, error) {
	attempts := r.maxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := r.backoff(ctx, attempt); err != nil {
				return nil, err
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, primaryAttemptTimeout)
		resp, err := r.primary.Complete(attemptCtx, p)
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err

		// Terminal conditions: don't retry on timeout/cancellation.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// backoff sleeps for an exponentially increasing delay with jitter, aborting
// early if the context is done.
func (r *LLMRouter) backoff(ctx context.Context, attempt int) error {
	base := r.baseBackoff
	if base <= 0 {
		base = defaultRouterBaseBackoff
	}
	delay := base * time.Duration(1<<(attempt-1))
	jitter := time.Duration(rand.Int63n(int64(base) + 1))

	timer := time.NewTimer(delay + jitter)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
