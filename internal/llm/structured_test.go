package llm

import (
	"context"
	"testing"
)

func TestParseStructuredExplanation_Valid(t *testing.T) {
	raw := `{"ai_explanation":"Domain must not import infrastructure","suggested_fix_diff":"- import x\n+ import y"}`
	s, err := ParseStructuredExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.AIExplanation != "Domain must not import infrastructure" {
		t.Errorf("AIExplanation = %q", s.AIExplanation)
	}
	if s.SuggestedFix != "- import x\n+ import y" {
		t.Errorf("SuggestedFix = %q", s.SuggestedFix)
	}
}

func TestParseStructuredExplanation_WithCodeFence(t *testing.T) {
	raw := "```json\n{\"ai_explanation\":\"boom\",\"suggested_fix_diff\":\"\"}\n```"
	s, err := ParseStructuredExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.AIExplanation != "boom" {
		t.Errorf("AIExplanation = %q, want %q", s.AIExplanation, "boom")
	}
}

func TestParseStructuredExplanation_Invalid(t *testing.T) {
	if _, err := ParseStructuredExplanation("this is not json at all"); err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}

func TestHeuristicProvider_StructuredOutput(t *testing.T) {
	provider := NewHeuristicProvider()

	resp, err := provider.Complete(context.Background(), Prompt{
		System: StructuredExplanationSystemPrompt,
		User:   "Description=Domain layer must not import infrastructure\nFromPkg=myapp/domain\nImport=myapp/infrastructure/db",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The heuristic backend must ALSO honor the structured contract: its Text
	// must be strict JSON parseable into a StructuredExplanation.
	s, err := ParseStructuredExplanation(resp.Text)
	if err != nil {
		t.Fatalf("heuristic output is not valid structured JSON: %v (text=%q)", err, resp.Text)
	}
	if s.AIExplanation == "" {
		t.Error("expected non-empty ai_explanation from heuristic structured output")
	}
}
