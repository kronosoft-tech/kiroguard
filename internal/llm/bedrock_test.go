package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// Compile-time interface compliance check.
var _ LLMBackend = (*BedrockProvider)(nil)

func TestBedrockProviderImplementsLLMBackend(t *testing.T) {
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

	if v, ok := payload["anthropic_version"].(string); !ok || v != "bedrock-2023-05-31" {
		t.Errorf("anthropic_version = %q, want %q", v, "bedrock-2023-05-31")
	}
	if v, ok := payload["max_tokens"].(float64); !ok || int(v) != 1024 {
		t.Errorf("max_tokens = %v, want 1024", payload["max_tokens"])
	}
	if v, ok := payload["system"].(string); !ok || v != "You are a security expert." {
		t.Errorf("system = %q, want %q", v, "You are a security expert.")
	}
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

	if _, exists := payload["system"]; exists {
		t.Error("system field should be omitted when empty")
	}
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

// mockBedrockServer returns an httptest.Server that responds with the given
// bedrockResponse JSON body.
func mockBedrockServer(body interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	}))
}

// newBedrockProviderForTest creates a BedrockProvider wired to a local
// test server using NewBedrockProviderWithClient. Caller must close the server.
func newBedrockProviderForTest(ts *httptest.Server) *BedrockProvider {
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: ts.URL, PartitionID: "aws"}, nil
	})
	cfg := aws.Config{
		Region:                      "us-east-1",
		Credentials:                 credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		EndpointResolverWithOptions: resolver,
	}
	client := bedrockruntime.NewFromConfig(cfg)
	return NewBedrockProviderWithClient(client, "test-model")
}

func TestBedrockComplete_HappyPath(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "text", Text: "Hello from Bedrock mock"},
		},
	})
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	resp, err := provider.Complete(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != "Hello from Bedrock mock" {
		t.Errorf("Text = %q, want %q", resp.Text, "Hello from Bedrock mock")
	}
}

func TestBedrockComplete_StructuredExplanationPrompt(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "text", Text: `{"ai_explanation":"violation","suggested_fix_diff":""}`},
		},
	})
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	resp, err := provider.Complete(context.Background(), Prompt{
		System: StructuredExplanationSystemPrompt,
		User:   "Analyze this import.",
	})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != `{"ai_explanation":"violation","suggested_fix_diff":""}` {
		t.Errorf("Text = %q", resp.Text)
	}
}

func TestBedrockComplete_ResponseNoTextBlock(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "tool_use", Text: ""},
		},
	})
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	resp, err := provider.Complete(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != "" {
		t.Errorf("Text = %q, want empty string when no text block", resp.Text)
	}
}

func TestBedrockComplete_EmptyContent(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{Content: []bedrockContentBlock{}})
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	resp, err := provider.Complete(context.Background(), Prompt{User: "hello"})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != "" {
		t.Errorf("Text = %q, want empty string", resp.Text)
	}
}

func TestBedrockComplete_InvokeModelError(t *testing.T) {
	// Server returns 500 → InvokeModel error path.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	_, err := provider.Complete(context.Background(), Prompt{User: "hello"})
	if err == nil {
		t.Fatal("expected error from InvokeModel failure")
	}
}

func TestBedrockComplete_UnmarshalError(t *testing.T) {
	// Server returns non-JSON body → json.Unmarshal error path.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not json}`))
	}))
	defer ts.Close()

	provider := newBedrockProviderForTest(ts)
	_, err := provider.Complete(context.Background(), Prompt{User: "hello"})
	if err == nil {
		t.Fatal("expected error from unmarshal failure")
	}
}

func TestBedrockNewProviderWithClient_EmptyModelID(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "text", Text: "ok"},
		},
	})
	defer ts.Close()

	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: ts.URL, PartitionID: "aws"}, nil
	})
	cfg := aws.Config{
		Region:                      "us-east-1",
		Credentials:                 credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		EndpointResolverWithOptions: resolver,
	}
	client := bedrockruntime.NewFromConfig(cfg)
	provider := NewBedrockProviderWithClient(client, "")
	if provider.modelID != DefaultBedrockModel {
		t.Errorf("modelID = %q, want %q", provider.modelID, DefaultBedrockModel)
	}
	resp, err := provider.Complete(context.Background(), Prompt{User: "x"})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("Text = %q, want %q", resp.Text, "ok")
	}
}

func TestBedrockNewProviderWithClient_CustomModelID(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "text", Text: "ok"},
		},
	})
	defer ts.Close()

	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: ts.URL, PartitionID: "aws"}, nil
	})
	cfg := aws.Config{
		Region:                      "us-east-1",
		Credentials:                 credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		EndpointResolverWithOptions: resolver,
	}
	client := bedrockruntime.NewFromConfig(cfg)
	provider := NewBedrockProviderWithClient(client, "custom-model")
	if provider.modelID != "custom-model" {
		t.Errorf("modelID = %q, want %q", provider.modelID, "custom-model")
	}
}

func TestBedrockComplete_ModelIDFromNewProvider(t *testing.T) {
	ts := mockBedrockServer(bedrockResponse{
		Content: []bedrockContentBlock{
			{Type: "text", Text: "ok"},
		},
	})
	defer ts.Close()

	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: ts.URL, PartitionID: "aws"}, nil
	})
	cfg := aws.Config{
		Region:                      "us-east-1",
		Credentials:                 credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		EndpointResolverWithOptions: resolver,
	}
	client := bedrockruntime.NewFromConfig(cfg)
	provider := &BedrockProvider{client: client, modelID: "test-model"}
	resp, err := provider.Complete(context.Background(), Prompt{User: "x"})
	if err != nil {
		t.Fatalf("Complete() error: %v", err)
	}
	if resp.Text != "ok" {
		t.Errorf("Text = %q, want %q", resp.Text, "ok")
	}
}
