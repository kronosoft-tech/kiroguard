package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StructuredExplanationSystemPrompt is the system prompt that obligates an LLM
// backend to respond with a strict JSON object containing exactly the keys
// "ai_explanation" and "suggested_fix_diff" (both strings) and nothing else.
//
// Callers that need machine-parseable enrichment (e.g. the Clean-Arch handler)
// set this as Prompt.System. Backends must honor it:
//   - BedrockProvider forwards it as the Anthropic system prompt so Claude emits JSON.
//   - HeuristicProvider synthesizes an equivalent JSON payload locally.
const StructuredExplanationSystemPrompt = "You are a senior software architect reviewing a Clean Architecture violation. " +
	"Respond ONLY with a strict, valid JSON object with exactly these two string keys: " +
	`"ai_explanation" (a concise explanation of why the import violates the architecture rule) and ` +
	`"suggested_fix_diff" (a unified-diff-style suggested refactor, or an empty string if none). ` +
	"Do not include any prose, markdown, or code fences outside the JSON object."

// StructuredExplanation is the parsed structured enrichment returned by a backend
// operating under StructuredExplanationSystemPrompt.
type StructuredExplanation struct {
	AIExplanation string `json:"ai_explanation"`
	SuggestedFix  string `json:"suggested_fix_diff"`
}

// ParseStructuredExplanation parses an LLM response body into a StructuredExplanation.
// It tolerates surrounding whitespace and Markdown code fences that some models
// wrap around JSON. It returns an error if no valid JSON object can be parsed.
func ParseStructuredExplanation(text string) (StructuredExplanation, error) {
	var s StructuredExplanation
	cleaned := extractJSON(text)
	if cleaned == "" {
		return StructuredExplanation{}, fmt.Errorf("no JSON object found in response")
	}
	if err := json.Unmarshal([]byte(cleaned), &s); err != nil {
		return StructuredExplanation{}, fmt.Errorf("parse structured explanation: %w", err)
	}
	return s, nil
}

// extractJSON strips optional Markdown code fences and returns the substring
// spanning the first "{" to the last "}". Returns "" if no braces are found.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return ""
	}
	return s[start : end+1]
}
