package llm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cbMockBackend struct {
	shouldFail bool
	calls      atomic.Int64
}

func (m *cbMockBackend) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	m.calls.Add(1)
	if m.shouldFail {
		return nil, errors.New("primary backend error")
	}
	return &LLMResponse{
		Text:     "primary response",
		Metadata: map[string]string{"provider": "primary"},
	}, nil
}

type cbFallbackBackend struct {
	calls atomic.Int64
}

func (f *cbFallbackBackend) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	f.calls.Add(1)
	return &LLMResponse{
		Text:     "fallback response",
		Metadata: map[string]string{"provider": "fallback"},
	}, nil
}

func TestCircuitBreaker_ClosedHappyPath(t *testing.T) {
	primary := &cbMockBackend{}
	fallback := &cbFallbackBackend{}
	cb := NewCircuitBreakerLLM(primary, fallback, 3, 100*time.Millisecond)

	resp, err := cb.Complete(context.Background(), Prompt{User: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "primary response" {
		t.Errorf("Text = %q, want primary response", resp.Text)
	}
	if primary.calls.Load() != 1 || fallback.calls.Load() != 0 {
		t.Errorf("primary calls=%d, fallback calls=%d", primary.calls.Load(), fallback.calls.Load())
	}
	if cb.Stats().State != StateClosed {
		t.Errorf("State = %s, want CLOSED", cb.Stats().State)
	}
}

func TestCircuitBreaker_OpensAfterThresholdFailures(t *testing.T) {
	primary := &cbMockBackend{shouldFail: true}
	fallback := &cbFallbackBackend{}
	cb := NewCircuitBreakerLLM(primary, fallback, 2, 50*time.Millisecond)

	// Call 1: primary fails, fallback succeeds, failures=1, state=CLOSED
	cb.Complete(context.Background(), Prompt{User: "test1"})
	if cb.Stats().State != StateClosed {
		t.Errorf("Call 1: State = %s, want CLOSED", cb.Stats().State)
	}

	// Call 2: primary fails, threshold 2 reached, state=OPEN
	cb.Complete(context.Background(), Prompt{User: "test2"})
	if cb.Stats().State != StateOpen {
		t.Errorf("Call 2: State = %s, want OPEN", cb.Stats().State)
	}

	// Call 3: circuit is OPEN: primary should NOT be called at all (0ms fail fast)
	primaryCallsBefore := primary.calls.Load()
	resp3, err := cb.Complete(context.Background(), Prompt{User: "test3"})
	if err != nil {
		t.Fatalf("unexpected error on fallback: %v", err)
	}
	if primary.calls.Load() != primaryCallsBefore {
		t.Errorf("primary called while OPEN: got %d calls, want %d", primary.calls.Load(), primaryCallsBefore)
	}
	if resp3.Metadata["circuit_breaker"] != "circuit_open" {
		t.Errorf("metadata = %v, want circuit_breaker=circuit_open", resp3.Metadata)
	}
}

func TestCircuitBreaker_HalfOpenRecovery(t *testing.T) {
	primary := &cbMockBackend{shouldFail: true}
	fallback := &cbFallbackBackend{}
	cooldown := 50 * time.Millisecond
	cb := NewCircuitBreakerLLM(primary, fallback, 1, cooldown)

	// Cause 1 failure to OPEN the circuit
	cb.Complete(context.Background(), Prompt{User: "test"})
	if cb.Stats().State != StateOpen {
		t.Fatalf("State = %s, want OPEN", cb.Stats().State)
	}

	// Wait for cooldown to elapse
	time.Sleep(cooldown + 10*time.Millisecond)

	// Primary recovers
	primary.shouldFail = false

	// Next call should probe primary in HALF_OPEN state and succeed, resetting circuit to CLOSED
	resp, err := cb.Complete(context.Background(), Prompt{User: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "primary response" {
		t.Errorf("Text = %q, want primary response", resp.Text)
	}
	if cb.Stats().State != StateClosed {
		t.Errorf("State after recovery = %s, want CLOSED", cb.Stats().State)
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	primary := &cbMockBackend{}
	fallback := &cbFallbackBackend{}
	cb := NewCircuitBreakerLLM(primary, fallback, 5, 100*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cb.Complete(context.Background(), Prompt{User: "concurrent"})
		}()
	}
	wg.Wait()
}
