package cleanarch

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// makeViolations writes n distinct domain->infrastructure violations into dir.
func makeViolations(t *testing.T, dir string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		content := "package domain\n\n" +
			"import \"github.com/myapp/infrastructure/db" + itoa(i) + "\"\n\n" +
			"var _ = db" + itoa(i) + ".Connect\n"
		createGoFile(t, filepathJoin(dir, "domain"), "service"+itoa(i)+".go", content)
	}
}

// filepathJoin avoids importing path/filepath twice across test files.
func filepathJoin(a, b string) string { return a + "/" + b }

func TestHandler_GlobalConcurrencyBoundedAcrossRequests(t *testing.T) {
	mock := &countingLLMBackend{text: "enriched"}
	notifier := &mockNotifier{}
	// Global cap of 3 shared across all requests.
	handler := NewCleanArchHandler(nil, mock, WithMaxConcurrent(3))
	handler.SetNotifier(notifier)

	// Two independent requests, each with several violations, fired concurrently.
	run := func(sess string) {
		dir := t.TempDir()
		makeViolations(t, dir, 6)
		params, _ := json.Marshal(CleanArchInput{DirectoryPath: dir})
		ctx := rpc.WithClientID(context.Background(), sess)
		if _, err := handler.Handle(ctx, params); err != nil {
			t.Errorf("Handle error: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); run("sess-A") }()
	go func() { defer wg.Done(); run("sess-B") }()
	wg.Wait()

	handler.waitBackground()

	if got := mock.max(); got > 3 {
		t.Errorf("global concurrent LLM calls = %d, want <= 3", got)
	}
}

func TestHandler_MaxEnrichmentsPerRequest(t *testing.T) {
	dir := t.TempDir()
	makeViolations(t, dir, 10)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"x","suggested_fix_diff":""}`},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock, WithMaxEnrichmentsPerRequest(3))
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: dir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	// All 10 violations are still reported in the response.
	output := result.(*CleanArchOutput)
	if len(output.Violations) != 10 {
		t.Fatalf("expected 10 violations in response, got %d", len(output.Violations))
	}

	handler.waitBackground()

	// But only 3 are enriched via notifications.
	if notifier.count() != 3 {
		t.Errorf("expected 3 enrichment notifications (capped), got %d", notifier.count())
	}
}

func TestHandler_ShutdownDrainsInflight(t *testing.T) {
	dir := t.TempDir()
	makeViolations(t, dir, 5)

	// Backend that takes a little time but always succeeds.
	mock := &countingLLMBackend{text: "enriched"}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: dir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	// Graceful shutdown must wait for in-flight enrichment to finish.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := handler.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	if notifier.count() != 5 {
		t.Errorf("expected all 5 enrichments delivered after drain, got %d", notifier.count())
	}
}

func TestHandler_MetricsSnapshot(t *testing.T) {
	dir := t.TempDir()
	makeViolations(t, dir, 4)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"x","suggested_fix_diff":""}`},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: dir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	handler.waitBackground()

	m := handler.MetricsSnapshot()
	if m.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", m.ScansTotal)
	}
	if m.ViolationsTotal != 4 {
		t.Errorf("ViolationsTotal = %d, want 4", m.ViolationsTotal)
	}
	if m.EnrichmentsOK != 4 {
		t.Errorf("EnrichmentsOK = %d, want 4", m.EnrichmentsOK)
	}
}
