package llm

import (
	"context"
	"time"
)

// LLMRouter wraps a primary and fallback LLMBackend. It attempts the primary
// provider first with a 10-second timeout and falls back to the secondary
// provider on any error.
type LLMRouter struct {
	primary  LLMBackend
	fallback LLMBackend
}

// NewLLMRouter creates an LLMRouter that tries primary first, then fallback.
func NewLLMRouter(primary, fallback LLMBackend) *LLMRouter {
	return &LLMRouter{
		primary:  primary,
		fallback: fallback,
	}
}

// Complete sends a prompt to the primary backend with a 10-second timeout.
// If the primary fails, it falls back to the secondary backend using the
// original context (without the timeout). On successful fallback, metadata
// includes "fallback" = "true".
func (r *LLMRouter) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := r.primary.Complete(timeoutCtx, p)
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
