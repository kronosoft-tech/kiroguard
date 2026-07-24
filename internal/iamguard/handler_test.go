package iamguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
