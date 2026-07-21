package cleanarch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

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

	handler := NewCleanArchHandler(nil)

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

	handler := NewCleanArchHandler(nil)

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
	handler := NewCleanArchHandler(nil)

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
	handler := NewCleanArchHandler(nil)

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

	handler := NewCleanArchHandler(nil)

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

	handler := NewCleanArchHandler(nil)

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
	handler := NewCleanArchHandler(nil)

	input := CleanArchInput{DirectoryPath: "/nonexistent/path/that/does/not/exist"}
	params, _ := json.Marshal(input)

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestHandler_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	handler := NewCleanArchHandler(nil)

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
	handler := NewCleanArchHandler(nil)

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
	handler := NewCleanArchHandler(nil)
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
	handler := NewCleanArchHandler(nil)
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
	handler := NewCleanArchHandler(customRules)
	if len(handler.defaultRules) != 1 {
		t.Errorf("expected 1 custom rule, got %d", len(handler.defaultRules))
	}
}
