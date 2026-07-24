package lambdaguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

func TestHandle_ValidScan(t *testing.T) {
	dir := t.TempDir()
	content := `
Resources:
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: nodejs20.x
      Timeout: 900
      MemorySize: 512
`
	os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(content), 0644)

	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{DirectoryPath: dir})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp, ok := result.(*Response)
	if !ok {
		t.Fatalf("result is not *Response")
	}
	if len(resp.Functions) != 1 {
		t.Errorf("got %d functions, want 1", len(resp.Functions))
	}
	if resp.Summary.TotalFunctions != 1 {
		t.Errorf("TotalFunctions = %d, want 1", resp.Summary.TotalFunctions)
	}
}

func TestHandle_EmptyDirectoryPath(t *testing.T) {
	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{DirectoryPath: ""})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for empty directory_path")
	}
	var ve *rpc.ValidationError
	if !asValidationError(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_NonexistentDirectory(t *testing.T) {
	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{DirectoryPath: "/nonexistent/path"})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
	var ve *rpc.ValidationError
	if !asValidationError(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_InvalidSeverityThreshold(t *testing.T) {
	dir := t.TempDir()
	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{
		DirectoryPath:     dir,
		SeverityThreshold: "invalid",
	})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for invalid severity_threshold")
	}
	var ve *rpc.ValidationError
	if !asValidationError(err, &ve) {
		t.Errorf("expected ValidationError, got %T", err)
	}
}

func TestHandle_NoFindings(t *testing.T) {
	dir := t.TempDir()
	content := `
Resources:
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: nodejs20.x
      Timeout: 30
      MemorySize: 512
      Description: My function
      ReservedConcurrentExecutions: 5
      Tracing: Active
`
	os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(content), 0644)

	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{DirectoryPath: dir})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp, ok := result.(*Response)
	if !ok {
		t.Fatalf("result is not *Response")
	}
	if resp.Summary.TotalFindings != 0 {
		t.Errorf("got %d findings, want 0: %+v", resp.Summary.TotalFindings, resp.Findings)
	}
}

func TestHandle_WithCriticalThreshold(t *testing.T) {
	dir := t.TempDir()
	content := `
Resources:
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: nodejs20.x
      Timeout: 910
      MemorySize: 512
`
	os.WriteFile(filepath.Join(dir, "template.yaml"), []byte(content), 0644)

	handler := NewLambdaGuardHandler(context.Background())
	params, _ := json.Marshal(Params{
		DirectoryPath:     dir,
		SeverityThreshold: "critical",
	})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	resp, ok := result.(*Response)
	if !ok {
		t.Fatalf("result is not *Response")
	}
	// LG-1 (timeout > 900) is "high", not "critical", so should be filtered out
	if resp.Summary.TotalFindings != 0 {
		t.Errorf("got %d findings with critical threshold, want 0", resp.Summary.TotalFindings)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	metrics := &Metrics{}
	metrics.AnalyzesTotal.Add(5)
	metrics.FunctionsTotal.Add(15)
	metrics.FindingsTotal.Add(30)
	metrics.CriticalFindings.Add(3)

	snap := MetricsSnapshot{
		AnalyzesTotal:    metrics.AnalyzesTotal.Load(),
		FunctionsTotal:   metrics.FunctionsTotal.Load(),
		FindingsTotal:    metrics.FindingsTotal.Load(),
		CriticalFindings: metrics.CriticalFindings.Load(),
	}

	if snap.AnalyzesTotal != 5 {
		t.Errorf("AnalyzesTotal = %d, want 5", snap.AnalyzesTotal)
	}
	if snap.FindingsTotal != 30 {
		t.Errorf("FindingsTotal = %d, want 30", snap.FindingsTotal)
	}
}

func TestShutdown(t *testing.T) {
	handler := NewLambdaGuardHandler(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := handler.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}
}

func TestOptions(t *testing.T) {
	metrics := &Metrics{}
	handler := NewLambdaGuardHandler(context.Background(),
		WithMetrics(metrics),
		WithSeverityThreshold("high"),
		WithMaxFileSizeMB(10),
		WithScanTimeout(30*time.Second),
		WithMetricsInterval(120*time.Second),
	)

	if handler.metrics != metrics {
		t.Error("WithMetrics not applied")
	}
	if handler.severityThreshold != "high" {
		t.Errorf("severityThreshold = %q, want high", handler.severityThreshold)
	}
	if handler.maxFileSizeMB != 10 {
		t.Errorf("maxFileSizeMB = %d, want 10", handler.maxFileSizeMB)
	}
	if handler.scanTimeout != 30*time.Second {
		t.Errorf("scanTimeout = %v, want 30s", handler.scanTimeout)
	}
	if handler.metricsInterval != 120*time.Second {
		t.Errorf("metricsInterval = %v, want 120s", handler.metricsInterval)
	}
}

func TestSeverityThresholdFilter(t *testing.T) {
	handler := NewLambdaGuardHandler(context.Background(), WithSeverityThreshold("high"))

	findings := []LambdaFinding{
		{CheckID: "low", Severity: "low"},
		{CheckID: "medium", Severity: "medium"},
		{CheckID: "high", Severity: "high"},
		{CheckID: "critical", Severity: "critical"},
	}

	filtered := handler.filterByThreshold(findings, "high")
	if len(filtered) != 2 {
		t.Fatalf("got %d filtered, want 2", len(filtered))
	}
	if filtered[0].CheckID != "high" {
		t.Errorf("first = %q, want high", filtered[0].CheckID)
	}
	if filtered[1].CheckID != "critical" {
		t.Errorf("second = %q, want critical", filtered[1].CheckID)
	}
}

func TestFilterByThreshold(t *testing.T) {
	handler := NewLambdaGuardHandler(context.Background())

	tests := []struct {
		threshold string
		expected  int
	}{
		{"low", 4},
		{"medium", 3},
		{"high", 2},
		{"critical", 1},
	}

	findings := []LambdaFinding{
		{CheckID: "a", Severity: "low"},
		{CheckID: "b", Severity: "medium"},
		{CheckID: "c", Severity: "high"},
		{CheckID: "d", Severity: "critical"},
	}

	for _, tt := range tests {
		filtered := handler.filterByThreshold(findings, tt.threshold)
		if len(filtered) != tt.expected {
			t.Errorf("threshold=%q: got %d, want %d", tt.threshold, len(filtered), tt.expected)
		}
	}
}

func asValidationError(err error, target **rpc.ValidationError) bool {
	if err == nil {
		return false
	}
	var ve *rpc.ValidationError
	if errors.As(err, &ve) {
		*target = ve
		return true
	}
	return false
}
