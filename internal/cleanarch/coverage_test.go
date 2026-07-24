package cleanarch

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// errNotifier returns a fixed error on every Send.
type errNotifier struct{}

func (e *errNotifier) Send(_ context.Context, _ *rpc.Response) error {
	return errors.New("send failed")
}

func TestWithScanTimeout(t *testing.T) {
	h := NewCleanArchHandler(nil, nil, WithScanTimeout(10*time.Second))
	if h.scanTimeout != 10*time.Second {
		t.Errorf("scanTimeout = %v, want 10s", h.scanTimeout)
	}

	h2 := NewCleanArchHandler(nil, nil, WithScanTimeout(0))
	if h2.scanTimeout != defaultScanTimeout {
		t.Errorf("scanTimeout = %v, want %v", h2.scanTimeout, defaultScanTimeout)
	}
}

func TestWithEnrichTimeout(t *testing.T) {
	h := NewCleanArchHandler(nil, nil, WithEnrichTimeout(2*time.Second))
	if h.enrichTimeout != 2*time.Second {
		t.Errorf("enrichTimeout = %v, want 2s", h.enrichTimeout)
	}

	h2 := NewCleanArchHandler(nil, nil, WithEnrichTimeout(0))
	if h2.enrichTimeout != defaultEnrichTimeout {
		t.Errorf("enrichTimeout = %v, want %v", h2.enrichTimeout, defaultEnrichTimeout)
	}
}

func TestReadSnippet_FileNotFound(t *testing.T) {
	got := readSnippet("/nonexistent/file.go", 5)
	if got != "" {
		t.Errorf("expected empty string for nonexistent file, got %q", got)
	}
}

func TestReadSnippet_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.go")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	got := readSnippet(path, 3)
	if got != "" {
		t.Errorf("expected empty string for empty file, got %q", got)
	}
}

func TestReadSnippet_FewerLinesThanRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.go")
	content := "line1\nline2"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := readSnippet(path, 2)
	if got != "line1\nline2" {
		t.Errorf("expected all available lines, got %q", got)
	}
}

func TestReadSnippet_StartLineBeyondTotalLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.go")
	content := "line1\nline2"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := readSnippet(path, 10)
	if got != "" {
		t.Errorf("expected empty string when start > total, got %q", got)
	}
}

func TestReadSnippet_EmptyPath(t *testing.T) {
	got := readSnippet("", 5)
	if got != "" {
		t.Errorf("expected empty string for empty path, got %q", got)
	}
}

func TestReadSnippet_NegativeLineNumber(t *testing.T) {
	got := readSnippet("some/file.go", -1)
	if got != "" {
		t.Errorf("expected empty string for negative line, got %q", got)
	}
}

func TestNodeImports(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", `package main

import (
	"fmt"
	"github.com/example/pkg"
	"os"
)
`, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}

	imports := nodeImports(f)
	if len(imports) != 3 {
		t.Fatalf("expected 3 imports, got %d: %v", len(imports), imports)
	}

	expected := []string{"fmt", "github.com/example/pkg", "os"}
	for i, imp := range imports {
		if imp != expected[i] {
			t.Errorf("import[%d] = %q, want %q", i, imp, expected[i])
		}
	}
}

func TestNodeImports_NoImports(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", `package main

func main() {}
`, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}

	imports := nodeImports(f)
	if len(imports) != 0 {
		t.Errorf("expected 0 imports, got %d", len(imports))
	}
}

func TestShutdown_CancelsBaseCtx(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)
	if err := handler.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
	if handler.baseCtx.Err() != context.Canceled {
		t.Errorf("baseCtx.Err() = %v, want Canceled", handler.baseCtx.Err())
	}
}

func TestStartMetricsReporter_ZeroInterval(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		handler.StartMetricsReporter(ctx, 0)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StartMetricsReporter did not return after context cancel")
	}
}

func TestEmitEnrichment_NotifierError(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)
	handler.notifier = &errNotifier{}

	err := handler.emitEnrichment(context.Background(), "req-1", 0, ArchViolation{
		FilePath: "test.go",
		Import:   "example.com/lib",
	}, llm.StructuredExplanation{AIExplanation: "explanation"})
	if err == nil {
		t.Fatal("expected error from emitEnrichment when notifier.Send fails")
	}
}

func TestStartBackgroundEnrichment_NilLLMResponse(t *testing.T) {
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, &mockLLMBackend{response: nil})
	handler.SetNotifier(notifier)

	violations := []ArchViolation{
		{FilePath: "test.go", LineNumber: 1, FromPkg: "pkg", Import: "example.com/lib"},
	}

	handler.startBackgroundEnrichment("sess-1", "req-1", violations)
	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications for nil response, got %d", notifier.count())
	}
}

func TestStartBackgroundEnrichment_EmptyLLMResponse(t *testing.T) {
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, &mockLLMBackend{
		response: &llm.LLMResponse{Text: "", Metadata: map[string]string{}},
	})
	handler.SetNotifier(notifier)

	violations := []ArchViolation{
		{FilePath: "test.go", LineNumber: 1, FromPkg: "pkg", Import: "example.com/lib"},
	}

	handler.startBackgroundEnrichment("sess-1", "req-1", violations)
	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications for empty response, got %d", notifier.count())
	}
}

func TestBuildPrompt_NoSourceSnippet(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)

	v := ArchViolation{
		FilePath:    "",
		LineNumber:  0,
		FromPkg:     "pkg",
		Import:      "example.com/lib",
		RuleName:    "**/a/** -> **/b/**",
		Description: "test violation",
	}

	prompt := handler.buildPrompt(v)
	if strings.Contains(prompt.User, "Snippet:") {
		t.Error("expected no snippet in prompt for empty file path")
	}
	if !strings.Contains(prompt.User, "Rule=**/a/** -> **/b/**") {
		t.Error("expected rule name in prompt")
	}
	if prompt.System != llm.StructuredExplanationSystemPrompt {
		t.Error("expected StructuredExplanationSystemPrompt")
	}
}

func TestParseFileImports_NoImports(t *testing.T) {
	tmpDir := t.TempDir()
	createGoFile(t, tmpDir, "main.go", `package main

func main() {}
`)

	edges, err := ParseFileImports(filepath.Join(tmpDir, "main.go"), tmpDir)
	if err != nil {
		t.Fatalf("ParseFileImports() error: %v", err)
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(edges))
	}
}

func TestReadSnippet_StartBelowZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	content := "line1\nline2\nline3"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	got := readSnippet(path, 1)
	if got != "line1\nline2" {
		t.Errorf("expected first two lines, got %q", got)
	}
}

func TestBuildPrompt_WithSourceSnippet(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.go")
	if err := os.WriteFile(filePath, []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	handler := NewCleanArchHandler(nil, nil)

	v := ArchViolation{
		FilePath:    filePath,
		LineNumber:  2,
		FromPkg:     "pkg",
		Import:      "example.com/lib",
		RuleName:    "**/a/** -> **/b/**",
		Description: "test violation",
	}

	prompt := handler.buildPrompt(v)
	if !strings.Contains(prompt.User, "Snippet:") {
		t.Error("expected snippet in prompt for valid file path")
	}
}

func TestShutdown_ForceCancelsInflightOnTimeout(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)

	handler.inflight.Add(1)
	go func() {
		defer handler.inflight.Done()
		<-handler.baseCtx.Done()
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := handler.Shutdown(shutdownCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error from Shutdown on timeout")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Shutdown took too long: %v", elapsed)
	}
}

func TestStartBackgroundEnrichment_ShutdownCancelsBlockedGoroutines(t *testing.T) {
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, &blockingLLMBackend{}, WithMaxConcurrent(1))
	handler.enrichTimeout = 10 * time.Second
	handler.SetNotifier(notifier)

	violations := make([]ArchViolation, 3)
	for i := range violations {
		violations[i] = ArchViolation{
			FilePath:   "test.go",
			LineNumber: i + 1,
			FromPkg:    "pkg",
			Import:     "example.com/lib",
		}
	}

	handler.startBackgroundEnrichment("sess-1", "req-1", violations)
	time.Sleep(20 * time.Millisecond)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := handler.Shutdown(shutdownCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error from Shutdown on timeout")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Shutdown took too long: %v", elapsed)
	}
}

func TestBuildImportGraphContext_ContextCancelledDuringWalk(t *testing.T) {
	tmpDir := t.TempDir()

	createGoFile(t, filepath.Join(tmpDir, "a"), "a.go", `package a

import "example.com/x"

var _ = x.Y
`)
	createGoFile(t, filepath.Join(tmpDir, "b"), "b.go", `package b

import "example.com/z"

var _ = z.W
`)

	// Context cancelled before walk — must return empty partial results, no error.
	earlyCtx, earlyCancel := context.WithCancel(context.Background())
	earlyCancel()

	graph, edges, err := BuildImportGraphContext(earlyCtx, tmpDir)
	if err != nil {
		t.Fatalf("expected no error on early cancellation, got %v", err)
	}
	if len(edges) != 0 {
		t.Errorf("expected 0 edges when pre-cancelled, got %d", len(edges))
	}
	if graph == nil {
		t.Error("expected non-nil graph")
	}
}
