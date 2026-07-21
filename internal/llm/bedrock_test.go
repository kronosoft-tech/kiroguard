package llm

import (
	"encoding/json"
	"testing"
)

// Compile-time interface compliance check.
var _ LLMBackend = (*BedrockProvider)(nil)

func TestBedrockProviderImplementsLLMBackend(t *testing.T) {
	// This test confirms that BedrockProvider satisfies the LLMBackend interface
	// at compile time via the var _ declaration above.
	// If BedrockProvider doesn't implement LLMBackend, compilation will fail.
	t.Log("BedrockProvider implements LLMBackend interface")
}

func TestBuildBedrockRequestPayload(t *testing.T) {
	prompt := Prompt{
		System: "You are a security expert.",
		User:   "Explain this vulnerability.",
	}

	data, err := BuildBedrockRequestPayload(prompt)
	if err != nil {
		t.Fatalf("BuildBedrockRequestPayload returned error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	// Verify anthropic_version
	if v, ok := payload["anthropic_version"].(string); !ok || v != "bedrock-2023-05-31" {
		t.Errorf("anthropic_version = %q, want %q", v, "bedrock-2023-05-31")
	}

	// Verify max_tokens
	if v, ok := payload["max_tokens"].(float64); !ok || int(v) != 1024 {
		t.Errorf("max_tokens = %v, want 1024", payload["max_tokens"])
	}

	// Verify system prompt
	if v, ok := payload["system"].(string); !ok || v != "You are a security expert." {
		t.Errorf("system = %q, want %q", v, "You are a security expert.")
	}

	// Verify messages array
	messages, ok := payload["messages"].([]interface{})
	if !ok || len(messages) != 1 {
		t.Fatalf("messages should have 1 element, got %v", payload["messages"])
	}

	msg, ok := messages[0].(map[string]interface{})
	if !ok {
		t.Fatal("first message is not a map")
	}

	if role, ok := msg["role"].(string); !ok || role != "user" {
		t.Errorf("message role = %q, want %q", msg["role"], "user")
	}

	if content, ok := msg["content"].(string); !ok || content != "Explain this vulnerability." {
		t.Errorf("message content = %q, want %q", msg["content"], "Explain this vulnerability.")
	}
}

func TestBuildBedrockRequestPayloadEmptySystem(t *testing.T) {
	prompt := Prompt{
		System: "",
		User:   "Hello",
	}

	data, err := BuildBedrockRequestPayload(prompt)
	if err != nil {
		t.Fatalf("BuildBedrockRequestPayload returned error: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	// When system is empty, the field should be omitted (omitempty tag)
	if _, exists := payload["system"]; exists {
		t.Error("system field should be omitted when empty")
	}

	// Messages should still be present
	messages, ok := payload["messages"].([]interface{})
	if !ok || len(messages) != 1 {
		t.Fatalf("messages should have 1 element, got %v", payload["messages"])
	}
}

func TestDefaultBedrockModel(t *testing.T) {
	expected := "anthropic.claude-3-sonnet-20240229-v1:0"
	if DefaultBedrockModel != expected {
		t.Errorf("DefaultBedrockModel = %q, want %q", DefaultBedrockModel, expected)
	}
}
