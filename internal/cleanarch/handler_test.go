package cleanarch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// mockLLMBackend is a hand-written mock implementing llm.LLMBackend for testing.
// No third-party mocking libraries are used.
type mockLLMBackend struct {
	response *llm.LLMResponse
	err      error
}

func (m *mockLLMBackend) Complete(_ context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	return m.response, m.err
}

// blockingLLMBackend simulates a hung LLM backend: it blocks until the context
// is cancelled (i.e. the per-call deadline fires) and then returns the context
// error. Used to verify the enrichment deadline + graceful fallback.
type blockingLLMBackend struct{}

func (b *blockingLLMBackend) Complete(ctx context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// countingLLMBackend records the maximum number of concurrent Complete calls in
// flight, so tests can assert the fan-out semaphore bounds concurrency.
type countingLLMBackend struct {
	mu      sync.Mutex
	current int
	maxSeen int
	text    string
}

func (c *countingLLMBackend) Complete(_ context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	c.mu.Lock()
	c.current++
	if c.current > c.maxSeen {
		c.maxSeen = c.current
	}
	c.mu.Unlock()

	// Hold the slot briefly to force overlap between concurrent calls.
	time.Sleep(15 * time.Millisecond)

	c.mu.Lock()
	c.current--
	c.mu.Unlock()

	// Honor the structured-output contract: return strict JSON.
	body := `{"ai_explanation":"` + c.text + `","suggested_fix_diff":""}`
	return &llm.LLMResponse{Text: body, Metadata: map[string]string{}}, nil
}

func (c *countingLLMBackend) max() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxSeen
}

func TestHandler_ValidAnalysisWithViolations(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a project structure that violates clean architecture rules.
	// domain imports infrastructure — this is a violation.
	createGoFile(t, filepath.Join(tmpDir, "domain"), "service.go", `package domain

import "github.com/myapp/infrastructure/database"

var _ = database.Connect
`)

	// infrastructure imports domain — this is allowed.
	createGoFile(t, filepath.Join(tmpDir, "infrastructure"), "repo.go", `package infrastructure

import "github.com/myapp/domain/model"

var _ = model.User{}
`)

	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{DirectoryPath: tmpDir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*CleanArchOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(output.Violations), output.Violations)
	}

	v := output.Violations[0]
	if v.Import != "github.com/myapp/infrastructure/database" {
		t.Errorf("violation import = %q, want %q", v.Import, "github.com/myapp/infrastructure/database")
	}
	if v.Description != "Domain layer must not import infrastructure" {
		t.Errorf("violation description = %q", v.Description)
	}

	if output.TotalEdges != 2 {
		t.Errorf("TotalEdges = %d, want 2", output.TotalEdges)
	}

	if output.Message == "" {
		t.Error("Message should not be empty")
	}
}

func TestHandler_ValidAnalysisNoViolations(t *testing.T) {
	tmpDir := t.TempDir()

	// Clean architecture: presentation → domain, infrastructure → domain (allowed)
	createGoFile(t, filepath.Join(tmpDir, "presentation"), "handler.go", `package presentation

import "github.com/myapp/domain/service"

var _ = service.Run
`)

	createGoFile(t, filepath.Join(tmpDir, "infrastructure"), "repo.go", `package infrastructure

import "github.com/myapp/domain/model"

var _ = model.User{}
`)

	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{DirectoryPath: tmpDir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*CleanArchOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Violations) != 0 {
		t.Fatalf("expected 0 violations, got %d: %+v", len(output.Violations), output.Violations)
	}

	if output.TotalEdges != 2 {
		t.Errorf("TotalEdges = %d, want 2", output.TotalEdges)
	}
}

func TestHandler_InvalidParams_EmptyDirectory(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{DirectoryPath: ""}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for empty directory_path")
	}

	expectedMsg := "invalid params: directory_path is required"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestHandler_InvalidParams_MalformedJSON(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)

	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestHandler_CustomRulesFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a custom rules file
	rulesContent := `rules:
  - from: "**/api/**"
    to: "**/database/**"
    allow: false
    description: "API must not directly access database"
`
	rulesFile := filepath.Join(tmpDir, "custom_rules.yaml")
	if err := os.WriteFile(rulesFile, []byte(rulesContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Create source files that violate the custom rule
	createGoFile(t, filepath.Join(tmpDir, "src", "api"), "handler.go", `package api

import "github.com/myapp/database/repo"

var _ = repo.Query
`)

	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{
		DirectoryPath: filepath.Join(tmpDir, "src"),
		RulesFile:     rulesFile,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*CleanArchOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Violations) != 1 {
		t.Fatalf("expected 1 violation with custom rules, got %d: %+v", len(output.Violations), output.Violations)
	}

	if output.Violations[0].Description != "API must not directly access database" {
		t.Errorf("violation description = %q", output.Violations[0].Description)
	}
}

func TestHandler_CustomRulesFile_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	createGoFile(t, tmpDir, "main.go", `package main

func main() {}
`)

	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{
		DirectoryPath: tmpDir,
		RulesFile:     "/nonexistent/rules.yaml",
	}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent rules file")
	}
}

func TestHandler_NonexistentDirectory(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{DirectoryPath: "/nonexistent/path/that/does/not/exist"}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestHandler_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	handler := NewCleanArchHandler(nil, nil)

	input := CleanArchInput{DirectoryPath: tmpDir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*CleanArchOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Violations) != 0 {
		t.Errorf("expected 0 violations for empty dir, got %d", len(output.Violations))
	}
	if output.TotalEdges != 0 {
		t.Errorf("TotalEdges = %d, want 0", output.TotalEdges)
	}
}

func TestRegisterCleanArch(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewCleanArchHandler(nil, nil)

	RegisterCleanArch(d, handler)

	// Verify the handler is registered by dispatching a valid request
	tmpDir := t.TempDir()
	createGoFile(t, tmpDir, "main.go", `package main

func main() {}
`)

	input := CleanArchInput{DirectoryPath: tmpDir}
	params, _ := json.Marshal(input)

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "cleanarch/analyze",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("dispatch returned error: %+v", resp.Error)
	}

	// Verify the response contains valid output
	var output CleanArchOutput
	if err := json.Unmarshal(resp.Result, &output); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if output.Message == "" {
		t.Error("expected non-empty message in response")
	}
}

func TestRegisterCleanArch_UnknownMethod(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewCleanArchHandler(nil, nil)
	RegisterCleanArch(d, handler)

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "cleanarch/unknown",
		Params:  nil,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != rpc.CodeMethodNotFound {
		t.Errorf("error code = %d, want %d", resp.Error.Code, rpc.CodeMethodNotFound)
	}
}

func TestNewCleanArchHandler_NilDefaultRules(t *testing.T) {
	handler := NewCleanArchHandler(nil, nil)
	if handler.defaultRules == nil {
		t.Fatal("defaultRules should not be nil when created with nil")
	}
	if len(handler.defaultRules) != 3 {
		t.Errorf("expected 3 default rules, got %d", len(handler.defaultRules))
	}
}

func TestNewCleanArchHandler_CustomDefaultRules(t *testing.T) {
	customRules := []Rule{
		{From: "**/a/**", To: "**/b/**", Allow: false, Desc: "custom rule"},
	}
	handler := NewCleanArchHandler(customRules, nil)
	if len(handler.defaultRules) != 1 {
		t.Errorf("expected 1 custom rule, got %d", len(handler.defaultRules))
	}
}

// mockNotifier captures notifications emitted by the handler. Thread-safe.
type mockNotifier struct {
	mu        sync.Mutex
	msgs      []*rpc.Response
	clientIDs []string // rpc.ClientID(ctx) observed per Send, index-aligned with msgs
}

func (m *mockNotifier) Send(ctx context.Context, msg *rpc.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	m.clientIDs = append(m.clientIDs, rpc.ClientID(ctx))
	return nil
}

func (m *mockNotifier) seenClientIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.clientIDs))
	copy(out, m.clientIDs)
	return out
}

func (m *mockNotifier) all() []*rpc.Response {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*rpc.Response, len(m.msgs))
	copy(out, m.msgs)
	return out
}

func (m *mockNotifier) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

// enrichmentNotificationData mirrors the "data" payload of an enrichment notification.
type enrichmentNotificationData struct {
	RequestID      string `json:"request_id"`
	ViolationIndex int    `json:"violation_index"`
	FilePath       string `json:"file_path"`
	Import         string `json:"import"`
	AIExplanation  string `json:"ai_explanation"`
	SuggestedFix   string `json:"suggested_fix_diff"`
}

func writeViolationFixture(t *testing.T, dir string) {
	t.Helper()
	createGoFile(t, filepath.Join(dir, "domain"), "service.go", `package domain

import "github.com/myapp/infrastructure/database"

var _ = database.Connect
`)
}

func TestHandler_ImmediateResponseHasNoInlineEnrichment(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{
			Text:     `{"ai_explanation":"async explanation","suggested_fix_diff":"- a\n+ b"}`,
			Metadata: map[string]string{},
		},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*CleanArchOutput)
	if len(output.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(output.Violations))
	}
	// The immediate response must contain the AST violation but NO inline enrichment.
	if output.Violations[0].AIExplanation != "" || output.Violations[0].SuggestedFix != "" {
		t.Errorf("expected no inline enrichment in immediate response, got %+v", output.Violations[0])
	}
	if output.Violations[0].Import != "github.com/myapp/infrastructure/database" {
		t.Errorf("violation import = %q", output.Violations[0].Import)
	}

	handler.waitBackground()
}

func TestHandler_EmitsEnrichmentNotification(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{
			Text:     `{"ai_explanation":"Domain must not depend on infrastructure.","suggested_fix_diff":"- import infra\n+ import port"}`,
			Metadata: map[string]string{},
		},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	handler.waitBackground()

	if notifier.count() != 1 {
		t.Fatalf("expected 1 enrichment notification, got %d", notifier.count())
	}

	msg := notifier.all()[0]
	if msg.ID != nil {
		t.Error("a notification must not carry an id")
	}
	if msg.Method != "notifications/message" {
		t.Errorf("notification method = %q, want notifications/message", msg.Method)
	}

	var p struct {
		Level  string                     `json:"level"`
		Logger string                     `json:"logger"`
		Data   enrichmentNotificationData `json:"data"`
	}
	if err := json.Unmarshal(msg.Params, &p); err != nil {
		t.Fatalf("failed to parse notification params: %v (raw=%s)", err, string(msg.Params))
	}
	if p.Data.AIExplanation != "Domain must not depend on infrastructure." {
		t.Errorf("notification ai_explanation = %q", p.Data.AIExplanation)
	}
	if p.Data.SuggestedFix != "- import infra\n+ import port" {
		t.Errorf("notification suggested_fix_diff = %q", p.Data.SuggestedFix)
	}
	if p.Data.Import != "github.com/myapp/infrastructure/database" {
		t.Errorf("notification import = %q", p.Data.Import)
	}
}

func TestHandler_MalformedJSONEmitsNoNotification(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{response: &llm.LLMResponse{Text: "totally not json"}}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected no notification on malformed JSON, got %d", notifier.count())
	}
}

func TestHandler_LLMErrorEmitsNoNotification(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{err: errors.New("bedrock unavailable")}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected no notification on LLM error, got %d", notifier.count())
	}
}

func TestHandler_EnrichmentTimeoutEmitsNoNotificationAndReturnsFast(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, &blockingLLMBackend{})
	handler.enrichTimeout = 50 * time.Millisecond
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")

	start := time.Now()
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}
	elapsed := time.Since(start)

	// The response must be immediate — it never waits on the LLM.
	if elapsed > 200*time.Millisecond {
		t.Fatalf("Handle() took %v, expected an immediate response", elapsed)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected no notification on enrichment timeout, got %d", notifier.count())
	}
}

func TestHandler_EnrichmentConcurrencyBounded(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate 12 distinct domain->infrastructure violations.
	const numViolations = 12
	for i := 0; i < numViolations; i++ {
		content := "package domain\n\n" +
			"import \"github.com/myapp/infrastructure/db" + itoa(i) + "\"\n\n" +
			"var _ = db" + itoa(i) + ".Connect\n"
		createGoFile(t, filepath.Join(tmpDir, "domain"), "service"+itoa(i)+".go", content)
	}

	mock := &countingLLMBackend{text: "enriched"}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*CleanArchOutput)
	if len(output.Violations) != numViolations {
		t.Fatalf("expected %d violations, got %d", numViolations, len(output.Violations))
	}

	handler.waitBackground()

	// The fan-out semaphore must cap concurrent LLM calls at 5.
	if got := mock.max(); got > 5 {
		t.Errorf("max concurrent LLM calls = %d, want <= 5", got)
	}
	// Every violation should be delivered as an enrichment notification.
	if notifier.count() != numViolations {
		t.Errorf("expected %d enrichment notifications, got %d", numViolations, notifier.count())
	}
}

func TestHandler_NoNotifierReturnsViolationsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"x","suggested_fix_diff":""}`},
	}
	// No notifier set → async enrichment is skipped entirely.
	handler := NewCleanArchHandler(nil, mock)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*CleanArchOutput)
	if len(output.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(output.Violations))
	}
	if output.Violations[0].AIExplanation != "" {
		t.Errorf("expected no enrichment without a notifier, got %q", output.Violations[0].AIExplanation)
	}

	handler.waitBackground() // must be a safe no-op when no background work ran
}

// itoa is a tiny local int-to-string helper to avoid importing strconv just for tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

func TestRegisterCleanArch_EmptyDirectoryReturnsInvalidParams(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewCleanArchHandler(nil, nil)
	RegisterCleanArch(d, handler)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: ""})
	reqID := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &reqID, Method: "cleanarch/analyze", Params: params}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for empty directory_path")
	}
	if resp.Error.Code != rpc.CodeInvalidParams {
		t.Errorf("error code = %d, want %d (Invalid Params)", resp.Error.Code, rpc.CodeInvalidParams)
	}
}

func TestRegisterCleanArch_MalformedJSONReturnsInvalidParams(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewCleanArchHandler(nil, nil)
	RegisterCleanArch(d, handler)

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &reqID, Method: "cleanarch/analyze", Params: json.RawMessage(`{invalid json`)}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if resp.Error.Code != rpc.CodeInvalidParams {
		t.Errorf("error code = %d, want %d (Invalid Params)", resp.Error.Code, rpc.CodeInvalidParams)
	}
}

func TestHandler_ScanTimeoutTruncationMessage(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	handler := NewCleanArchHandler(nil, nil)
	// A near-zero scan deadline forces the AST walk to abort immediately,
	// yielding partial results plus a truncation note.
	handler.scanTimeout = time.Nanosecond

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*CleanArchOutput)
	if !strings.Contains(output.Message, "truncated") {
		t.Errorf("expected truncation note in message, got %q", output.Message)
	}
}

func TestHandler_EnrichmentNotificationCarriesClientID(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"x","suggested_fix_diff":""}`},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	// The request arrives with a session id in the context.
	ctx := rpc.WithClientID(context.Background(), "sess-xyz")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	handler.waitBackground()

	ids := notifier.seenClientIDs()
	if len(ids) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(ids))
	}
	// The async notification must be routed to the originating session.
	if ids[0] != "sess-xyz" {
		t.Errorf("notification client id = %q, want %q", ids[0], "sess-xyz")
	}
}

func TestHandler_NoSessionSkipsEnrichmentAndSignals(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"x","suggested_fix_diff":""}`},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	// No client/session id in the context → enrichment must be skipped, never
	// broadcast to unrelated clients.
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected no notifications without a session, got %d", notifier.count())
	}

	output := result.(*CleanArchOutput)
	if !strings.Contains(output.Message, "skipped") {
		t.Errorf("expected message to signal enrichment was skipped, got %q", output.Message)
	}
	if output.RequestID != "" {
		t.Errorf("expected empty request_id when enrichment is skipped, got %q", output.RequestID)
	}
}

func TestHandler_ResponseAndNotificationShareRequestID(t *testing.T) {
	tmpDir := t.TempDir()
	writeViolationFixture(t, tmpDir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"ai_explanation":"e","suggested_fix_diff":""}`},
	}
	notifier := &mockNotifier{}
	handler := NewCleanArchHandler(nil, mock)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(CleanArchInput{DirectoryPath: tmpDir})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*CleanArchOutput)
	if output.RequestID == "" {
		t.Fatal("expected a non-empty request_id in the response when enrichment runs")
	}

	handler.waitBackground()

	if notifier.count() != 1 {
		t.Fatalf("expected 1 notification, got %d", notifier.count())
	}

	var p struct {
		Data enrichmentNotificationData `json:"data"`
	}
	if err := json.Unmarshal(notifier.all()[0].Params, &p); err != nil {
		t.Fatalf("failed to parse notification params: %v", err)
	}
	if p.Data.RequestID != output.RequestID {
		t.Errorf("notification request_id = %q, want %q (from response)", p.Data.RequestID, output.RequestID)
	}
}
