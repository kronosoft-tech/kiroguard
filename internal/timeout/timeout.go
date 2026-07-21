package timeout

import (
	"context"
	"time"
)

// DefaultExternalTimeout is the standard timeout for all external service calls
// (OSV.dev, AWS Secrets Manager/SSM, Bedrock) as specified in requirement 9.3.
const DefaultExternalTimeout = 10 * time.Second

// WithTimeout wraps a function call with a context timeout.
// It creates a derived context with the specified deadline and passes it to fn.
// If fn doesn't complete within the duration, the context is cancelled and fn
// should observe ctx.Done() and return a context.DeadlineExceeded error.
func WithTimeout(ctx context.Context, d time.Duration, fn func(context.Context) error) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return fn(timeoutCtx)
}
