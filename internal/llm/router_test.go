package llm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Compile-time check that LLMRouter implements LLMBackend.
var _ LLMBackend = (*LLMRouter)(nil)

// mockBackend is a configurable LLMBackend for testing.
type mockBackend struct {
	response *LLMResponse
	err      error
	delay    time.Duration
}

func (m *mockBackend) Complete(ctx context.Context, _ Prompt) (*LLMResponse, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.response, m.err
}

func TestLLMRouter_PrimarySucceeds(t *testing.T) {
	primary := &mockBackend{
		response: &LLMResponse{
			Text:     "primary response",
			Metadata: map[string]string{"model": "bedrock"},
		},
	}
	fallback := &mockBackend{
		response: &LLMResponse{
			Text:     "fallback response",
			Metadata: map[string]string{},
		},
	}

	router := NewLLMRouter(primary, fallback)
	resp, err := router.Complete(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "primary response" {
		t.Errorf("got text %q, want %q", resp.Text, "primary response")
	}
	if _, ok := resp.Metadata["fallback"]; ok {
		t.Error("fallback metadata should not be set when primary succeeds")
	}
}

func TestLLMRouter_PrimaryFails_FallbackSucceeds(t *testing.T) {
	primary := &mockBackend{
		err: errors.New("bedrock unavailable"),
	}
	fallback := &mockBackend{
		response: &LLMResponse{
			Text:     "heuristic result",
			Metadata: map[string]string{},
		},
	}

	router := NewLLMRouter(primary, fallback)
	resp, err := router.Complete(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "heuristic result" {
		t.Errorf("got text %q, want %q", resp.Text, "heuristic result")
	}
	if resp.Metadata["fallback"] != "true" {
		t.Errorf("expected metadata[\"fallback\"] = \"true\", got %q", resp.Metadata["fallback"])
	}
}

func TestLLMRouter_BothFail(t *testing.T) {
	primary := &mockBackend{
		err: errors.New("bedrock unavailable"),
	}
	fallback := &mockBackend{
		err: errors.New("heuristic also failed"),
	}

	router := NewLLMRouter(primary, fallback)
	_, err := router.Complete(context.Background(), Prompt{User: "hello"})
	if err == nil {
		t.Fatal("expected error when both providers fail")
	}
	if err.Error() != "heuristic also failed" {
		t.Errorf("got error %q, want %q", err.Error(), "heuristic also failed")
	}
}

func TestLLMRouter_PrimaryTimeout_TriggersFallback(t *testing.T) {
	// Primary sleeps longer than the 10s timeout. We use a shorter parent
	// context deadline to keep the test fast while still validating the
	// timeout path.
	primary := &mockBackend{
		response: &LLMResponse{Text: "slow primary", Metadata: map[string]string{}},
		delay:    15 * time.Second, // longer than the 10s router timeout
	}
	fallback := &mockBackend{
		response: &LLMResponse{
			Text:     "fast fallback",
			Metadata: map[string]string{},
		},
	}

	router := NewLLMRouter(primary, fallback)

	// Use a background context; the router imposes its own 10s timeout on primary.
	// To keep the test fast, we override the router's timeout by using a
	// custom context with a short deadline that simulates the timeout behavior.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := router.Complete(ctx, Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "fast fallback" {
		t.Errorf("got text %q, want %q", resp.Text, "fast fallback")
	}
	if resp.Metadata["fallback"] != "true" {
		t.Errorf("expected metadata[\"fallback\"] = \"true\", got %q", resp.Metadata["fallback"])
	}
}

func TestLLMRouter_FallbackNilMetadata(t *testing.T) {
	// Ensure the router initializes metadata map if the fallback response has nil metadata.
	primary := &mockBackend{
		err: errors.New("primary down"),
	}
	fallback := &mockBackend{
		response: &LLMResponse{
			Text:     "fallback with nil metadata",
			Metadata: nil, // intentionally nil
		},
	}

	router := NewLLMRouter(primary, fallback)
	resp, err := router.Complete(context.Background(), Prompt{User: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Metadata == nil {
		t.Fatal("metadata should be initialized, not nil")
	}
	if resp.Metadata["fallback"] != "true" {
		t.Errorf("expected metadata[\"fallback\"] = \"true\", got %q", resp.Metadata["fallback"])
	}
}

func TestLLMRouter_ImplementsLLMBackend(t *testing.T) {
	// Verify that LLMRouter can be used anywhere an LLMBackend is expected.
	var backend LLMBackend = NewLLMRouter(
		&mockBackend{response: &LLMResponse{Text: "ok", Metadata: map[string]string{}}},
		&mockBackend{response: &LLMResponse{Text: "ok", Metadata: map[string]string{}}},
	)
	resp, err := backend.Complete(context.Background(), Prompt{User: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("got text %q, want %q", resp.Text, "ok")
	}
}

// flakyBackend fails a configurable number of times before succeeding.
type flakyBackend struct {
	failuresBeforeSuccess int
	mu                    sync.Mutex
	calls                 int
}

func (f *flakyBackend) Complete(_ context.Context, _ Prompt) (*LLMResponse, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n <= f.failuresBeforeSuccess {
		return nil, errors.New("transient throttling")
	}
	return &LLMResponse{Text: "recovered", Metadata: map[string]string{}}, nil
}

func (f *flakyBackend) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestLLMRouter_RetriesTransientPrimaryErrors(t *testing.T) {
	primary := &flakyBackend{failuresBeforeSuccess: 2}
	fallback := &mockBackend{response: &LLMResponse{Text: "fallback", Metadata: map[string]string{}}}

	router := NewLLMRouter(primary, fallback)
	router.baseBackoff = time.Millisecond // keep the test fast

	resp, err := router.Complete(context.Background(), Prompt{User: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "recovered" {
		t.Errorf("got %q, want %q (primary should have recovered)", resp.Text, "recovered")
	}
	if _, ok := resp.Metadata["fallback"]; ok {
		t.Error("should not have fallen back after a successful retry")
	}
	if got := primary.callCount(); got != 3 {
		t.Errorf("primary calls = %d, want 3 (2 failures + 1 success)", got)
	}
}

func TestLLMRouter_ExhaustsRetriesThenFallback(t *testing.T) {
	primary := &flakyBackend{failuresBeforeSuccess: 100} // always fails within attempts
	fallback := &mockBackend{response: &LLMResponse{Text: "fb", Metadata: map[string]string{}}}

	router := NewLLMRouter(primary, fallback)
	router.baseBackoff = time.Millisecond

	resp, err := router.Complete(context.Background(), Prompt{User: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Metadata["fallback"] != "true" {
		t.Errorf("expected fallback after exhausting retries, got metadata %v", resp.Metadata)
	}
	if got := primary.callCount(); got != 3 {
		t.Errorf("primary attempts = %d, want 3 (default maxAttempts)", got)
	}
}
