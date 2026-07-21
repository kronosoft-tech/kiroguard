package finops

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// mockLLM implements llm.LLMBackend for testing.
type mockLLM struct {
	response *llm.LLMResponse
	err      error
}

func (m *mockLLM) Complete(_ context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	return m.response, m.err
}

// sourceWithNPlusOne is Go source code containing an N+1 query pattern.
const sourceWithNPlusOne = `package main

import "database/sql"

func getUsers(db *sql.DB, ids []int) {
	for _, id := range ids {
		db.QueryRow("SELECT * FROM users WHERE id = ?", id)
	}
}
`

// sourceWithUnpaginatedScan contains a DynamoDB Scan without Limit.
const sourceWithUnpaginatedScan = `package main

import "github.com/aws/aws-sdk-go-v2/service/dynamodb"

func scanAll(client *dynamodb.Client) {
	client.Scan(context.TODO(), &dynamodb.ScanInput{
		TableName: &tableName,
	})
}
`

// sourceWithLambdaNoConfig contains a Lambda CreateFunctionInput missing MemorySize and Timeout.
const sourceWithLambdaNoConfig = `package main

import "github.com/aws/aws-sdk-go-v2/service/lambda"

func createFunc(client *lambda.Client) {
	input := lambda.CreateFunctionInput{
		FunctionName: &name,
		Runtime:      "go1.x",
	}
	_ = input
}
`

// sourceClean has no expensive patterns.
const sourceClean = `package main

func hello() string {
	return "hello"
}
`

func TestFinOpsHandler_NPlusOneDetection(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode:      sourceWithNPlusOne,
		FilePath:        "main.go",
		RequestsPerHour: 1000,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Findings) == 0 {
		t.Fatal("expected at least 1 finding for N+1 query pattern")
	}

	finding := output.Findings[0]
	if finding.PatternType != string(PatternN1Query) {
		t.Errorf("PatternType = %q, want %q", finding.PatternType, PatternN1Query)
	}
	if finding.FilePath != "main.go" {
		t.Errorf("FilePath = %q, want %q", finding.FilePath, "main.go")
	}
	if finding.LineNumber <= 0 {
		t.Errorf("LineNumber = %d, want > 0", finding.LineNumber)
	}
	if finding.EstimatedCost <= 0 {
		t.Errorf("EstimatedCost = %f, want > 0", finding.EstimatedCost)
	}
	if finding.Formula == "" {
		t.Error("Formula should not be empty")
	}
	if finding.Explanation == "" {
		t.Error("Explanation should not be empty")
	}
	if output.TotalCost <= 0 {
		t.Errorf("TotalCost = %f, want > 0", output.TotalCost)
	}
}

func TestFinOpsHandler_NoPatterns(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode: sourceClean,
		FilePath:   "clean.go",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(output.Findings))
	}
	if output.TotalCost != 0 {
		t.Errorf("TotalCost = %f, want 0", output.TotalCost)
	}
	if output.Message == "" {
		t.Error("Message should not be empty")
	}
}

func TestFinOpsHandler_EmptySourceCode(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode: "",
		FilePath:   "empty.go",
	}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for empty source_code")
	}

	expected := "invalid params: source_code is required"
	if err.Error() != expected {
		t.Errorf("error = %q, want %q", err.Error(), expected)
	}
}

func TestFinOpsHandler_MalformedJSON(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	_, err := handler.Handle(context.Background(), json.RawMessage(`{invalid json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestFinOpsHandler_InvalidGoSource(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode: "this is not valid Go source code at all {{{",
		FilePath:   "bad.go",
	}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for invalid Go source")
	}
}

func TestFinOpsHandler_DefaultRequestsPerHour(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	// RequestsPerHour not set (zero value) — should use default 1000
	input := FinOpsInput{
		SourceCode: sourceWithNPlusOne,
		FilePath:   "main.go",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Findings) == 0 {
		t.Fatal("expected findings even without explicit requests_per_hour")
	}

	// With default 1000 rph, the cost should be calculable
	if output.TotalCost <= 0 {
		t.Errorf("TotalCost = %f, want > 0 with default rph", output.TotalCost)
	}
}

func TestFinOpsHandler_WithLLMBackend(t *testing.T) {
	mock := &mockLLM{
		response: &llm.LLMResponse{
			Text:     "LLM-generated explanation with $73.00/month cost breakdown",
			Metadata: map[string]string{},
		},
		err: nil,
	}

	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), mock)

	input := FinOpsInput{
		SourceCode:      sourceWithNPlusOne,
		FilePath:        "main.go",
		RequestsPerHour: 1000,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Findings) == 0 {
		t.Fatal("expected findings")
	}

	// With LLM available, explanation should come from LLM
	if output.Findings[0].Explanation != "LLM-generated explanation with $73.00/month cost breakdown" {
		t.Errorf("expected LLM explanation, got: %q", output.Findings[0].Explanation)
	}
}

func TestFinOpsHandler_LLMFallbackOnError(t *testing.T) {
	mock := &mockLLM{
		response: nil,
		err:      errors.New("bedrock timeout"),
	}

	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), mock)

	input := FinOpsInput{
		SourceCode:      sourceWithNPlusOne,
		FilePath:        "main.go",
		RequestsPerHour: 500,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	if len(output.Findings) == 0 {
		t.Fatal("expected findings")
	}

	// When LLM fails, should fallback to heuristic explanation with dollar amounts
	explanation := output.Findings[0].Explanation
	if explanation == "" {
		t.Error("expected heuristic explanation on LLM failure")
	}
	// Should contain dollar amount
	if !containsDollarAmount(explanation) {
		t.Errorf("heuristic explanation should contain dollar amount, got: %q", explanation)
	}
}

func TestFinOpsHandler_TotalCostSumsFindings(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode:      sourceWithLambdaNoConfig,
		FilePath:        "lambda.go",
		RequestsPerHour: 1000,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	// Lambda without both MemorySize and Timeout should produce 2 findings
	if len(output.Findings) < 2 {
		t.Fatalf("expected at least 2 findings for lambda missing memory and timeout, got %d", len(output.Findings))
	}

	// TotalCost should equal sum of individual costs
	var sum float64
	for _, f := range output.Findings {
		sum += f.EstimatedCost
	}
	sum = roundTo2Decimals(sum)

	if output.TotalCost != sum {
		t.Errorf("TotalCost = %f, want sum of findings = %f", output.TotalCost, sum)
	}
}

func TestFinOpsHandler_HeuristicExplanationsContainDollarAmounts(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	input := FinOpsInput{
		SourceCode:      sourceWithNPlusOne,
		FilePath:        "main.go",
		RequestsPerHour: 2000,
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle() error: %v", err)
	}

	output, ok := result.(*FinOpsOutput)
	if !ok {
		t.Fatalf("unexpected result type: %T", result)
	}

	for i, f := range output.Findings {
		if !containsDollarAmount(f.Explanation) {
			t.Errorf("finding[%d] explanation missing dollar amount: %q", i, f.Explanation)
		}
	}
}

func TestRegisterFinOps(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)

	RegisterFinOps(d, handler)

	// Verify the handler is registered by dispatching a valid request
	input := FinOpsInput{
		SourceCode: sourceClean,
		FilePath:   "main.go",
	}
	params, _ := json.Marshal(input)

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "finops/analyze",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("dispatch returned error: %+v", resp.Error)
	}

	var output FinOpsOutput
	if err := json.Unmarshal(resp.Result, &output); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if output.Message == "" {
		t.Error("expected non-empty message in response")
	}
}

func TestRegisterFinOps_UnknownMethod(t *testing.T) {
	d := rpc.NewDispatcher()
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)
	RegisterFinOps(d, handler)

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "finops/unknown",
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

func TestNewFinOpsHandler_NilLLM(t *testing.T) {
	handler := NewFinOpsHandler(NewPatternDetector(), NewCostEstimator(1000), nil)
	if handler == nil {
		t.Fatal("handler should not be nil")
	}
	if handler.llm != nil {
		t.Error("llm should be nil when created with nil")
	}
}

// containsDollarAmount checks if a string contains a dollar sign followed by digits.
func containsDollarAmount(s string) bool {
	for i, c := range s {
		if c == '$' && i+1 < len(s) {
			next := s[i+1]
			if next >= '0' && next <= '9' {
				return true
			}
		}
	}
	return false
}
