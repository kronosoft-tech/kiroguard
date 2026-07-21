// Package llm defines the pluggable LLM backend interface and providers.
package llm

import "context"

// Prompt represents a structured prompt for an LLM backend.
type Prompt struct {
	System string
	User   string
}

// LLMResponse contains the generated text and metadata from an LLM call.
type LLMResponse struct {
	Text     string            `json:"text"`
	Metadata map[string]string `json:"metadata"`
}

// LLMBackend defines the interface for LLM providers.
type LLMBackend interface {
	Complete(ctx context.Context, p Prompt) (*LLMResponse, error)
}
