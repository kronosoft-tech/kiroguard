package llm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

type cacheMockBackend struct {
	calls atomic.Int64
	fail  bool
}

func (m *cacheMockBackend) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	m.calls.Add(1)
	if m.fail {
		return nil, errors.New("backend error")
	}
	return &LLMResponse{
		Text:     fmt.Sprintf("response for %s", p.User),
		Metadata: map[string]string{"provider": "mock"},
	}, nil
}

func TestCachedLLM_HitAndMiss(t *testing.T) {
	mock := &cacheMockBackend{}
	cached := NewCachedLLM(mock, 10)

	prompt := Prompt{System: "sys", User: "hello"}

	// First call: Miss
	resp1, err := cached.Complete(context.Background(), prompt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls.Load() != 1 {
		t.Errorf("calls = %d, want 1", mock.calls.Load())
	}
	if resp1.Metadata["cached"] == "true" {
		t.Errorf("expected uncached response on first call")
	}

	// Second call: Hit
	resp2, err := cached.Complete(context.Background(), prompt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (cache hit)", mock.calls.Load())
	}
	if resp2.Metadata["cached"] != "true" {
		t.Errorf("expected cached = true on second call")
	}
	if resp2.Text != resp1.Text {
		t.Errorf("Text = %q, want %q", resp2.Text, resp1.Text)
	}

	stats := cached.Stats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want Hits=1, Misses=1", stats)
	}
}

func TestCachedLLM_Eviction(t *testing.T) {
	mock := &cacheMockBackend{}
	capacity := 2
	cached := NewCachedLLM(mock, capacity)

	p1 := Prompt{User: "p1"}
	p2 := Prompt{User: "p2"}
	p3 := Prompt{User: "p3"}

	cached.Complete(context.Background(), p1) // misses=1, size=1
	cached.Complete(context.Background(), p2) // misses=2, size=2
	cached.Complete(context.Background(), p3) // misses=3, evicts p1, size=2

	stats := cached.Stats()
	if stats.Evictions != 1 {
		t.Errorf("Evictions = %d, want 1", stats.Evictions)
	}
	if stats.Size != 2 {
		t.Errorf("Size = %d, want 2", stats.Size)
	}

	// p1 should now miss because it was evicted
	mock.calls.Store(0)
	cached.Complete(context.Background(), p1)
	if mock.calls.Load() != 1 {
		t.Errorf("p1 should have missed after eviction")
	}
}

func TestCachedLLM_ErrorNotCached(t *testing.T) {
	mock := &cacheMockBackend{fail: true}
	cached := NewCachedLLM(mock, 10)

	prompt := Prompt{User: "error_test"}
	_, err := cached.Complete(context.Background(), prompt)
	if err == nil {
		t.Fatalf("expected error")
	}

	mock.fail = false
	resp, err := cached.Complete(context.Background(), prompt)
	if err != nil {
		t.Fatalf("expected success after backend recovery: %v", err)
	}
	if resp.Text != "response for error_test" {
		t.Errorf("Text = %q, want response for error_test", resp.Text)
	}
}

func TestCachedLLM_ConcurrentAccess(t *testing.T) {
	mock := &cacheMockBackend{}
	cached := NewCachedLLM(mock, 50)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			prompt := Prompt{User: fmt.Sprintf("user_%d", id%5)} // 5 unique prompts across 20 workers
			_, err := cached.Complete(context.Background(), prompt)
			if err != nil {
				t.Errorf("concurrent Complete error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	stats := cached.Stats()
	if stats.Size > 5 {
		t.Errorf("Size = %d, want <= 5", stats.Size)
	}
}

func TestCachedLLM_Clear(t *testing.T) {
	mock := &mockBackend{}
	cached := NewCachedLLM(mock, 10)

	p := Prompt{User: "test"}
	cached.Complete(context.Background(), p)
	if cached.Stats().Size != 1 {
		t.Fatalf("Size = %d, want 1", cached.Stats().Size)
	}

	cached.Clear()
	if cached.Stats().Size != 0 {
		t.Fatalf("Size = %d after Clear, want 0", cached.Stats().Size)
	}
}
