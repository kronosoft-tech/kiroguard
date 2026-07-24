package piiguard

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

func TestHandle_ValidScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const key = "AKIA1234567890123456"
`)
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{DirectoryPath: dir})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp, ok := result.(*PIIResponse)
	if !ok {
		t.Fatalf("result is not *PIIResponse")
	}
	if len(resp.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if resp.Summary.TotalFindings == 0 {
		t.Errorf("TotalFindings = 0, expected > 0")
	}
	if resp.ScanTimeMs < 0 {
		t.Errorf("ScanTimeMs = %d, expected >= 0", resp.ScanTimeMs)
	}
}

func TestHandle_EmptyDirectoryPath(t *testing.T) {
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{DirectoryPath: ""})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for empty directory_path")
	}
	var ve *rpc.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_InvalidSeverityThreshold(t *testing.T) {
	dir := t.TempDir()
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{
		DirectoryPath:     dir,
		SeverityThreshold: "invalid",
	})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for invalid severity_threshold")
	}
	var ve *rpc.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_NonexistentDirectory(t *testing.T) {
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{DirectoryPath: "/nonexistent/path"})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
	var ve *rpc.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_NoLLM(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const key = "AKIA1234567890123456"
`)
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{DirectoryPath: dir})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp := result.(*PIIResponse)
	if resp.RequestID != "" {
		t.Errorf("expected no request_id without LLM, got %q", resp.RequestID)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	m := &Metrics{}
	m.ScansTotal.Add(3)
	m.FindingsTotal.Add(15)
	m.CriticalFindings.Add(2)
	m.VerificationsOK.Add(1)
	m.VerificationsFailed.Add(0)

	snap := MetricsSnapshot{
		ScansTotal:          m.ScansTotal.Load(),
		FindingsTotal:       m.FindingsTotal.Load(),
		CriticalFindings:    m.CriticalFindings.Load(),
		VerificationsOK:     m.VerificationsOK.Load(),
		VerificationsFailed: m.VerificationsFailed.Load(),
	}

	if snap.ScansTotal != 3 {
		t.Errorf("ScansTotal = %d, want 3", snap.ScansTotal)
	}
	if snap.FindingsTotal != 15 {
		t.Errorf("FindingsTotal = %d, want 15", snap.FindingsTotal)
	}
	if snap.CriticalFindings != 2 {
		t.Errorf("CriticalFindings = %d, want 2", snap.CriticalFindings)
	}
}

func TestShutdown(t *testing.T) {
	handler := NewPIIGuardHandler()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := handler.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}
}

func TestOptions(t *testing.T) {
	metrics := &Metrics{}
	handler := NewPIIGuardHandler(
		WithMetrics(metrics),
		WithSeverityThreshold("high"),
		WithMaxFileSizeMB(5),
		WithEntropyThreshold(4.0),
		WithScanTimeout(30*time.Second),
		WithEnrichTimeout(10*time.Second),
		WithMaxConcurrent(5),
		WithMetricsInterval(120*time.Second),
	)

	if handler.opts.severityThreshold != "high" {
		t.Errorf("severityThreshold = %q, want high", handler.opts.severityThreshold)
	}
	if handler.opts.maxFileSizeMB != 5 {
		t.Errorf("maxFileSizeMB = %d, want 5", handler.opts.maxFileSizeMB)
	}
	if handler.opts.entropyThreshold != 4.0 {
		t.Errorf("entropyThreshold = %f, want 4.0", handler.opts.entropyThreshold)
	}
}

func TestHandle_CriticalThreshold(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const email = "test@example.com"
const key = "AKIA1234567890123456"
`)
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{
		DirectoryPath:     dir,
		SeverityThreshold: "critical",
	})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp := result.(*PIIResponse)
	// Email is "low", AWS key is "critical" → only critical survives filter
	for _, f := range resp.Findings {
		if f.PatternType == "email" {
			t.Error("email should be filtered out at critical threshold")
		}
	}
}

func TestHandle_EntropyCheckDisabled(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const x = "X8kL1mN2oP4qR6sT8uV0wX2yZ4aB3dE5fG7hI9"
`)
	falseVal := false
	handler := NewPIIGuardHandler()
	params, _ := json.Marshal(PIIParams{
		DirectoryPath: dir,
		EntropyCheck:  &falseVal,
	})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp := result.(*PIIResponse)
	for _, f := range resp.Findings {
		if f.PatternType == "high_entropy_string" {
			t.Error("entropy finding should not appear when entropy_check=false")
		}
	}
}

type mockNotifier struct {
	sent chan *rpc.Response
}

func (m *mockNotifier) Send(ctx context.Context, msg *rpc.Response) error {
	select {
	case m.sent <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type mockLLM struct {
	response string
	err      error
}

func (m *mockLLM) Complete(ctx context.Context, prompt llm.Prompt) (*llm.LLMResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	text := m.response
	if text == "" {
		text = `[{"pattern_type":"aws_access_key","is_true_positive":true,"reason":"valid AWS key"}]`
	}
	return &llm.LLMResponse{Text: text}, nil
}

func TestHandle_WithEnrichment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const key = "AKIA1234567890123456"
`)
	notifier := &mockNotifier{sent: make(chan *rpc.Response, 1)}
	handler := NewPIIGuardHandler(
		WithLLM(&mockLLM{}),
		WithNotifier(notifier),
	)
	params, _ := json.Marshal(PIIParams{DirectoryPath: dir})

	ctx := rpc.WithClientID(context.Background(), "test-session")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp := result.(*PIIResponse)
	if resp.RequestID == "" {
		t.Error("expected request_id when enrichment is configured")
	}

	// Give background goroutine time to complete
	time.Sleep(200 * time.Millisecond)

	select {
	case <-notifier.sent:
		// OK
	default:
		t.Error("expected notification to be sent")
	}
}

func TestHandle_EnrichmentLLMError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const key = "AKIA1234567890123456"
`)
	notifier := &mockNotifier{sent: make(chan *rpc.Response, 1)}
	handler := NewPIIGuardHandler(
		WithLLM(&mockLLM{err: errors.New("llm error")}),
		WithNotifier(notifier),
	)
	params, _ := json.Marshal(PIIParams{DirectoryPath: dir})

	ctx := rpc.WithClientID(context.Background(), "test-session")
	_, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	// Give background goroutine time to fail
	for i := 0; i < 20; i++ {
		if handler.metrics.VerificationsFailed.Load() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if handler.metrics.VerificationsFailed.Load() != 1 {
		t.Errorf("expected 1 verification failure, got %d", handler.metrics.VerificationsFailed.Load())
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []PIIFinding{
		{PatternType: "email", Severity: "low"},
		{PatternType: "phone", Severity: "low"},
		{PatternType: "ip", Severity: "medium"},
		{PatternType: "ssn", Severity: "high"},
		{PatternType: "aws_key", Severity: "critical"},
	}

	filtered := filterBySeverity(findings, "high")
	if len(filtered) != 2 {
		t.Errorf("expected 2 findings at high threshold, got %d", len(filtered))
	}

	filtered = filterBySeverity(findings, "low")
	if len(filtered) != 5 {
		t.Errorf("expected 5 findings at low threshold, got %d", len(filtered))
	}

	filtered = filterBySeverity(findings, "critical")
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding at critical threshold, got %d", len(filtered))
	}
}

func TestGroupByFile(t *testing.T) {
	findings := []PIIFinding{
		{FilePath: "a.go", PatternType: "email"},
		{FilePath: "a.go", PatternType: "key"},
		{FilePath: "b.go", PatternType: "email"},
	}
	groups := groupByFile(findings)
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
	if len(groups[0]) != 2 {
		t.Errorf("group[0] expected 2, got %d", len(groups[0]))
	}
}

func TestParseVerdicts(t *testing.T) {
	group := []PIIFinding{
		{FilePath: "a.go", LineNumber: 1, PatternType: "aws_access_key"},
		{FilePath: "a.go", LineNumber: 2, PatternType: "email"},
	}
	text := `[{"pattern_type":"aws_access_key","is_true_positive":true,"reason":"valid key"},{"pattern_type":"email","is_true_positive":false,"reason":"test data"}]`

	verdicts, err := parseVerdicts(text, group)
	if err != nil {
		t.Fatalf("parseVerdicts error: %v", err)
	}
	if len(verdicts) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(verdicts))
	}
	if !verdicts[0].IsTruePositive {
		t.Error("expected first verdict to be true positive")
	}
	if verdicts[1].IsTruePositive {
		t.Error("expected second verdict to be false positive")
	}
}

func TestParseVerdicts_InvalidJSON(t *testing.T) {
	_, err := parseVerdicts("not json", nil)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
