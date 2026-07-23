package llm

import (
	"context"
	"encoding/json"
	"fmt"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// DefaultBedrockModel is the default Bedrock model ID used when none is specified.
const DefaultBedrockModel = "anthropic.claude-3-sonnet-20240229-v1:0"

// BedrockProvider implements LLMBackend using AWS Bedrock InvokeModel.
type BedrockProvider struct {
	client  *bedrockruntime.Client
	modelID string
}

// bedrockRequest represents the Anthropic Messages API payload for Bedrock.
type bedrockRequest struct {
	AnthropicVersion string           `json:"anthropic_version"`
	MaxTokens        int              `json:"max_tokens"`
	System           string           `json:"system,omitempty"`
	Messages         []bedrockMessage `json:"messages"`
}

// bedrockMessage represents a single message in the Anthropic Messages API.
type bedrockMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// bedrockResponse represents the response from the Anthropic Messages API on Bedrock.
type bedrockResponse struct {
	Content []bedrockContentBlock `json:"content"`
}

// bedrockContentBlock represents a content block in the Bedrock response.
type bedrockContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// NewBedrockProvider creates a provider using the AWS default credential chain.
// If modelID is empty, DefaultBedrockModel is used.
func NewBedrockProvider(ctx context.Context, region string, modelID string) (*BedrockProvider, error) {
	if modelID == "" {
		modelID = DefaultBedrockModel
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(cfg)

	return &BedrockProvider{
		client:  client,
		modelID: modelID,
	}, nil
}

// Complete sends a prompt to Bedrock and returns the response.
func (b *BedrockProvider) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	// Structured-output requests may carry a unified diff, so give them a larger
	// token budget to avoid truncating the JSON payload. The system prompt itself
	// (StructuredExplanationSystemPrompt) is forwarded unchanged so Claude emits
	// strict JSON with ai_explanation and suggested_fix_diff.
	maxTokens := 1024
	if p.System == StructuredExplanationSystemPrompt {
		maxTokens = 2048
	}

	payload := bedrockRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		MaxTokens:        maxTokens,
		System:           p.System,
		Messages: []bedrockMessage{
			{Role: "user", Content: p.User},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request payload: %w", err)
	}

	contentType := "application/json"
	output, err := b.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     &b.modelID,
		ContentType: &contentType,
		Body:        body,
	})
	if err != nil {
		return nil, fmt.Errorf("bedrock InvokeModel failed: %w", err)
	}

	var resp bedrockResponse
	if err := json.Unmarshal(output.Body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse bedrock response: %w", err)
	}

	// Extract text from the first text content block.
	var text string
	for _, block := range resp.Content {
		if block.Type == "text" {
			text = block.Text
			break
		}
	}

	return &LLMResponse{
		Text:     text,
		Metadata: map[string]string{},
	}, nil
}

// BuildBedrockRequestPayload constructs the Anthropic Messages API payload.
// Exported for testing purposes.
func BuildBedrockRequestPayload(p Prompt) ([]byte, error) {
	payload := bedrockRequest{
		AnthropicVersion: "bedrock-2023-05-31",
		MaxTokens:        1024,
		System:           p.System,
		Messages: []bedrockMessage{
			{Role: "user", Content: p.User},
		},
	}
	return json.Marshal(payload)
}
