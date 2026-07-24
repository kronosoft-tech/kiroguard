package iamguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// mockLLMBackend is a hand-written mock implementing llm.LLMBackend.
type mockLLMBackend struct {
	response *llm.LLMResponse
	err      error
}

func (m *mockLLMBackend) Complete(_ context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	return m.response, m.err
}

// mockNotifier captures notifications emitted by the handler. Thread-safe.
type mockNotifier struct {
	mu   sync.Mutex
	msgs []*rpc.Response
}

func (m *mockNotifier) Send(_ context.Context, msg *rpc.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
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

// policyEnrichmentData mirrors the "data" payload of a PolicyEnrichment notification.
type policyEnrichmentData struct {
	RequestID     string `json:"request_id"`
	IAMPolicyJSON string `json:"iam_policy_json"`
	AWSActions    string `json:"aws_actions"`
}

// writeSDKFixture creates a .go file with AWS SDK calls for testing.
func writeSDKFixture(t *testing.T, dir string) {
	t.Helper()
	content := `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
	client.PutObject(ctx, nil)
}
`
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeIaCFixture creates a JSON file with a wildcard IAM statement.
func writeIaCFixture(t *testing.T, dir string) {
	t.Helper()
	content := `{"Action": "*", "Resource": "arn:aws:s3:::my-bucket/*"}`
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandle_ValidWithActions(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)

	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*IAMGuardOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	if len(output.Actions) == 0 {
		t.Fatal("expected at least 1 action")
	}
	if output.Message == "" {
		t.Error("message should not be empty")
	}
}

func TestHandle_ValidWithWildcards(t *testing.T) {
	dir := t.TempDir()
	writeIaCFixture(t, dir)

	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*IAMGuardOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	if len(output.Wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
}

func TestHandle_MixedSDKAndIaC(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)
	writeIaCFixture(t, dir)

	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*IAMGuardOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	if len(output.Actions) == 0 {
		t.Fatal("expected at least 1 action")
	}
	if len(output.Wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
}

func TestHandle_NoAWSFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main; func main() {}`), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*IAMGuardOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}
	if len(output.Actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(output.Actions))
	}
}

func TestHandle_EmptyDirectoryPath(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: ""}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for empty directory_path")
	}
}

func TestHandle_MalformedJSON(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestHandle_NonexistentDirectory(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: "/nonexistent/path/that/does/not/exist"}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestHandle_InvalidParamsWrapsValidationError(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid json}`))
	if err == nil {
		t.Fatal("expected error")
	}
	var valErr *rpc.ValidationError
	if !errors.As(err, &valErr) {
		t.Fatal("expected error to wrap *rpc.ValidationError")
	}
}

func TestHandle_PathIsFileNotDirectory(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	filePath := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(filePath, []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	input := IAMGuardInput{DirectoryPath: filePath}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for file path (not a directory)")
	}
	var valErr *rpc.ValidationError
	if !errors.As(err, &valErr) {
		t.Fatal("expected error to wrap *rpc.ValidationError")
	}
}

func TestHandle_StatPermissionError(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)

	input := IAMGuardInput{DirectoryPath: subdir}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for permission-denied path")
	}
}

func TestHandle_AsyncPolicyNotification(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{
			Text:     `{"iam_policy_json":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\",\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}","aws_actions":"s3:GetObject, s3:PutObject"}`,
			Metadata: map[string]string{},
		},
	}
	notifier := &mockNotifier{}
	handler := NewIAMGuardHandler(mock)
	handler.SetNotifier(notifier)

	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)
	ctx := rpc.WithClientID(context.Background(), "sess-1")

	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*IAMGuardOutput)
	if output.RequestID == "" {
		t.Fatal("expected non-empty request_id")
	}

	handler.waitBackground()

	if notifier.count() != 1 {
		t.Fatalf("expected 1 notification, got %d", notifier.count())
	}

	msg := notifier.all()[0]
	if msg.Method != "notifications/message" {
		t.Errorf("notification method = %q, want notifications/message", msg.Method)
	}

	var p struct {
		Data policyEnrichmentData `json:"data"`
	}
	if err := json.Unmarshal(msg.Params, &p); err != nil {
		t.Fatalf("failed to parse notification params: %v", err)
	}
	if p.Data.RequestID != output.RequestID {
		t.Errorf("notification request_id = %q, want %q", p.Data.RequestID, output.RequestID)
	}
	if p.Data.IAMPolicyJSON == "" {
		t.Error("expected non-empty iam_policy_json")
	}
}

func TestHandle_AsyncPolicyErrorGraceful(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)

	mock := &mockLLMBackend{err: errors.New("bedrock unavailable")}
	notifier := &mockNotifier{}
	handler := NewIAMGuardHandler(mock)
	handler.SetNotifier(notifier)

	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)
	ctx := rpc.WithClientID(context.Background(), "sess-1")

	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*IAMGuardOutput)
	if output.RequestID == "" {
		t.Fatal("expected request_id even when LLM will fail")
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on LLM error, got %d", notifier.count())
	}
}

type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStartMetricsReporter_EmitsOnInterval(t *testing.T) {
	var lb lockedBuf
	handler := NewIAMGuardHandler(nil)
	handler.logger = slog.New(slog.NewTextHandler(&lb, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := context.WithCancel(context.Background())
	go handler.StartMetricsReporter(ctx, 20*time.Millisecond)

	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if !strings.Contains(lb.String(), "metrics_report") {
		t.Error("expected metrics_report event in log output")
	}
}

func TestStartMetricsReporter_IntervalZero(t *testing.T) {
	var lb lockedBuf
	handler := NewIAMGuardHandler(nil)
	handler.logger = slog.New(slog.NewTextHandler(&lb, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := context.WithCancel(context.Background())
	go handler.StartMetricsReporter(ctx, 0)

	time.Sleep(10 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	if !strings.Contains(lb.String(), "metrics_report") {
		t.Error("expected metrics_report on cancel even with interval=0")
	}
}

func TestHandle_NoNotifierNoEnrichment(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"iam_policy_json":"{}","aws_actions":"s3:GetObject"}`},
	}
	handler := NewIAMGuardHandler(mock)

	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*IAMGuardOutput)
	if output.RequestID != "" {
		t.Errorf("expected no request_id without notifier, got %q", output.RequestID)
	}

	handler.waitBackground()

	// No notifications should have been sent.
	// Can't check notifier since it's nil.
}

func TestHandle_NoSessionIDNoEnrichment(t *testing.T) {
	dir := t.TempDir()
	writeSDKFixture(t, dir)

	mock := &mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"iam_policy_json":"{}","aws_actions":"s3:GetObject"}`},
	}
	notifier := &mockNotifier{}
	handler := NewIAMGuardHandler(mock)
	handler.SetNotifier(notifier)

	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output := result.(*IAMGuardOutput)
	if output.RequestID != "" {
		t.Errorf("expected no request_id without session, got %q", output.RequestID)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications without session, got %d", notifier.count())
	}
}

func TestStartBackgroundPolicyGen_NilResponse(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{response: nil})
	notifier := &mockNotifier{}
	h.SetNotifier(notifier)

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on nil response, got %d", notifier.count())
	}
}

func TestStartBackgroundPolicyGen_EmptyText(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{
		response: &llm.LLMResponse{Text: ""},
	})
	notifier := &mockNotifier{}
	h.SetNotifier(notifier)

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on empty text, got %d", notifier.count())
	}
}

func TestStartBackgroundPolicyGen_ShutdownDuringSemaphore(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"iam_policy_json":"{}","aws_actions":"s3:GetObject"}`},
	})
	notifier := &mockNotifier{}
	h.SetNotifier(notifier)

	for i := 0; i < h.maxConcurrent; i++ {
		h.globalSem <- struct{}{}
	}

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.baseCancel()
	h.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on shutdown during semaphore, got %d", notifier.count())
	}
}

type errNotifier struct{}

func (e *errNotifier) Send(_ context.Context, _ *rpc.Response) error {
	return errors.New("send failed")
}

func TestStartBackgroundPolicyGen_LLMDeadlineExceeded(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{err: context.DeadlineExceeded})
	notifier := &mockNotifier{}
	h.SetNotifier(notifier)

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on DeadlineExceeded, got %d", notifier.count())
	}
}

func TestStartBackgroundPolicyGen_ParseError(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{
		response: &llm.LLMResponse{Text: `not valid json at all`},
	})
	notifier := &mockNotifier{}
	h.SetNotifier(notifier)

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected 0 notifications on parse error, got %d", notifier.count())
	}
}

func TestStartBackgroundPolicyGen_EmitPolicyError(t *testing.T) {
	h := NewIAMGuardHandler(&mockLLMBackend{
		response: &llm.LLMResponse{Text: `{"iam_policy_json":"{\"Version\":\"2012-10-17\"}","aws_actions":"s3:GetObject"}`},
	})
	h.SetNotifier(&errNotifier{})

	h.startBackgroundPolicyGen("sess-1", "req-1",
		[]AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}, nil)
	h.waitBackground()
}

func TestRegisterIAMGuard(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewIAMGuardHandler(nil)
	RegisterIAMGuard(d, handler)

	dir := t.TempDir()
	writeSDKFixture(t, dir)

	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)
	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "iamguard/analyze",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("dispatch returned error: %+v", resp.Error)
	}

	var output IAMGuardOutput
	if err := json.Unmarshal(resp.Result, &output); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if output.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestNewRequestID_Format(t *testing.T) {
	id := newRequestID()
	if len(id) != 16 {
		t.Fatalf("request_id length = %d, want 16", len(id))
	}
}

func TestBuildPrompt_WithActions(t *testing.T) {
	actions := []AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 2}}
	prompt := buildPrompt(actions, nil)
	if !strings.Contains(prompt.User, "s3:GetObject") {
		t.Error("prompt should include action details")
	}
	if !strings.Contains(prompt.User, "count: 2") {
		t.Error("prompt should include action count")
	}
	if !strings.Contains(prompt.System, "iam_policy_json") {
		t.Error("system prompt should request JSON output")
	}
}

func TestBuildPrompt_WithWildcards(t *testing.T) {
	actions := []AWSAction{{Service: "s3", Action: "s3:GetObject", Count: 1}}
	wildcards := []IACWildcard{{
		FilePath: "policy.json", LineNumber: 3,
		Statement: `"Action": "*"`, Risk: "critical",
	}}
	prompt := buildPrompt(actions, wildcards)
	if !strings.Contains(prompt.User, "policy.json") {
		t.Error("prompt should include wildcard file path")
	}
	if !strings.Contains(prompt.User, "Wildcard") {
		t.Error("prompt should mention wildcards section")
	}
}

func TestParsePolicyResponse_Valid(t *testing.T) {
	text := `{"iam_policy_json":"{\"Version\":\"2012-10-17\"}","aws_actions":"s3:GetObject"}`
	policyJSON, awsActions, err := parsePolicyResponse(text)
	if err != nil {
		t.Fatal(err)
	}
	if policyJSON == "" {
		t.Error("expected non-empty policy JSON")
	}
	if awsActions != "s3:GetObject" {
		t.Errorf("aws_actions = %q, want %q", awsActions, "s3:GetObject")
	}
}

func TestParsePolicyResponse_InvalidJSON(t *testing.T) {
	_, _, err := parsePolicyResponse("{invalid}")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParsePolicyResponse_Empty(t *testing.T) {
	_, _, err := parsePolicyResponse(`{"iam_policy_json":"","aws_actions":""}`)
	if err == nil {
		t.Fatal("expected error for empty iam_policy_json")
	}
}

func TestNewIAMGuardHandler_DefaultValues(t *testing.T) {
	h := NewIAMGuardHandler(nil)
	if h.enrichTimeout != 5*time.Second {
		t.Errorf("default enrichTimeout = %v, want 5s", h.enrichTimeout)
	}
	if h.scanTimeout != 10*time.Second {
		t.Errorf("default scanTimeout = %v, want 10s", h.scanTimeout)
	}
	if h.maxConcurrent != 3 {
		t.Errorf("default maxConcurrent = %d, want 3", h.maxConcurrent)
	}
}

func TestNewIAMGuardHandler_WithEnrichTimeout(t *testing.T) {
	h := NewIAMGuardHandler(nil, WithEnrichTimeout(2*time.Second))
	if h.enrichTimeout != 2*time.Second {
		t.Errorf("enrichTimeout = %v, want 2s", h.enrichTimeout)
	}
}

func TestNewIAMGuardHandler_WithScanTimeout(t *testing.T) {
	h := NewIAMGuardHandler(nil, WithScanTimeout(30*time.Second))
	if h.scanTimeout != 30*time.Second {
		t.Errorf("scanTimeout = %v, want 30s", h.scanTimeout)
	}
}

func TestNewIAMGuardHandler_WithMaxConcurrent(t *testing.T) {
	h := NewIAMGuardHandler(nil, WithMaxConcurrent(10))
	if h.maxConcurrent != 10 {
		t.Errorf("maxConcurrent = %d, want 10", h.maxConcurrent)
	}
}

func TestNewIAMGuardHandler_WithMaxFileSize(t *testing.T) {
	h := NewIAMGuardHandler(nil, WithMaxFileSize(999))
	if h.maxFileSize != 999 {
		t.Errorf("maxFileSize = %d, want 999", h.maxFileSize)
	}
}

func TestNewIAMGuardHandler_WithMaxFileSizeZero(t *testing.T) {
	h := NewIAMGuardHandler(nil, WithMaxFileSize(0))
	if h.maxFileSize != defaultMaxIACFileSize {
		t.Errorf("maxFileSize = %d, want default %d", h.maxFileSize, defaultMaxIACFileSize)
	}
}

func TestMetricsSnapshot_InitialZero(t *testing.T) {
	h := NewIAMGuardHandler(nil)
	m := h.MetricsSnapshot()
	if m.ScansTotal != 0 || m.WildcardsTotal != 0 || m.PoliciesOK != 0 || m.PoliciesFailed != 0 {
		t.Errorf("expected all zero, got %+v", m)
	}
}

func TestMetricsSnapshot_AfterScan(t *testing.T) {
	dir := t.TempDir()
	writeIaCFixture(t, dir)

	h := NewIAMGuardHandler(nil)
	input := IAMGuardInput{DirectoryPath: dir}
	params, _ := json.Marshal(input)
	if _, err := h.Handle(context.Background(), params); err != nil {
		t.Fatal(err)
	}

	m := h.MetricsSnapshot()
	if m.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", m.ScansTotal)
	}
	if m.WildcardsTotal != 1 {
		t.Errorf("WildcardsTotal = %d, want 1", m.WildcardsTotal)
	}
}

func TestShutdown_DrainsInflight(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	handler.inflight.Add(1)

	done := make(chan struct{})
	go func() {
		handler.Shutdown(context.Background())
		close(done)
	}()

	// Let Shutdown start waiting
	time.Sleep(10 * time.Millisecond)

	// Complete the inflight work
	handler.inflight.Done()

	select {
	case <-done:
		// ok
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not drain inflight in time")
	}
}

func TestShutdown_CancelsBaseCtx(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	handler.inflight.Add(1)

	done := make(chan struct{})
	go func() {
		handler.Shutdown(context.Background())
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	handler.inflight.Done()
	<-done

	if handler.baseCtx.Err() == nil {
		t.Error("baseCtx should be cancelled after Shutdown")
	}
}

func TestShutdown_TimeoutExpires(t *testing.T) {
	handler := NewIAMGuardHandler(nil)
	handler.inflight.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	errCh := make(chan error)
	go func() {
		errCh <- handler.Shutdown(ctx)
	}()

	<-ctx.Done()
	handler.inflight.Done()

	err := <-errCh
	if err == nil {
		t.Error("expected error on context timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}
}
