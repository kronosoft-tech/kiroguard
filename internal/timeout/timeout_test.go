package timeout

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWithTimeout_CompletesBeforeDeadline(t *testing.T) {
	ctx := context.Background()

	err := WithTimeout(ctx, 1*time.Second, func(ctx context.Context) error {
		// Completes immediately — well within the 1s timeout.
		return nil
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestWithTimeout_ReturnsErrorFromFunction(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("operation failed")

	err := WithTimeout(ctx, 1*time.Second, func(ctx context.Context) error {
		return expectedErr
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got: %v", expectedErr, err)
	}
}

func TestWithTimeout_ExceedsTimeout(t *testing.T) {
	ctx := context.Background()

	start := time.Now()
	err := WithTimeout(ctx, 50*time.Millisecond, func(ctx context.Context) error {
		// Simulate a slow external call that respects context cancellation.
		select {
		case <-time.After(5 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}

	// Should complete close to the 50ms timeout, not the 5s sleep.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("expected to complete near 50ms, took %v", elapsed)
	}
}

func TestWithTimeout_PreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately before calling WithTimeout.

	err := WithTimeout(ctx, 1*time.Second, func(ctx context.Context) error {
		// The context should already be cancelled.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestDefaultExternalTimeout_Value(t *testing.T) {
	if DefaultExternalTimeout != 10*time.Second {
		t.Fatalf("expected DefaultExternalTimeout to be 10s, got %v", DefaultExternalTimeout)
	}
}
