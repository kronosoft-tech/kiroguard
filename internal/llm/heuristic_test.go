package llm

import (
	"context"
	"testing"
)

func TestHeuristicProvider_KnownTemplate(t *testing.T) {
	provider := NewHeuristicProvider()

	tests := []struct {
		name     string
		template string
		user     string
		want     string
	}{
		{
			name:     "vuln_explanation template",
			template: "template:vuln_explanation",
			user:     "CVE=CVE-2023-1234\nSeverity=9.8\nAffectedRange=<1.2.0\nFixedVersion=1.2.0",
			want:     `Vulnerability CVE-2023-1234 (severity 9.8) affects versions <1.2.0. Upgrade to 1.2.0 to resolve this issue.`,
		},
		{
			name:     "finops_explanation template",
			template: "template:finops_explanation",
			user:     "PatternType=N+1 Query\nFilePath=main.go\nLineNumber=42\nEstimatedCost=15.30\nRequestsPerHour=1000",
			want:     `Pattern "N+1 Query" detected at main.go:42. Estimated monthly cost: $15.30 based on 1000 requests/hour.`,
		},
		{
			name:     "secret_explanation template",
			template: "template:secret_explanation",
			user:     "SecretType=AWS Access Key\nFilePath=config.go\nLineNumber=10",
			want:     `A AWS Access Key secret was detected at config.go:10. Rotate this credential immediately and use a secrets manager reference instead.`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := provider.Complete(context.Background(), Prompt{
				System: tt.template,
				User:   tt.user,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Text != tt.want {
				t.Errorf("got:\n  %q\nwant:\n  %q", resp.Text, tt.want)
			}
			if resp.Metadata == nil {
				t.Error("metadata should not be nil")
			}
		})
	}
}

func TestHeuristicProvider_UnknownTemplate_Passthrough(t *testing.T) {
	provider := NewHeuristicProvider()

	input := "This is a raw user prompt"
	resp, err := provider.Complete(context.Background(), Prompt{
		System: "template:nonexistent_template",
		User:   input,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != input {
		t.Errorf("expected passthrough, got %q, want %q", resp.Text, input)
	}
}

func TestHeuristicProvider_NoTemplatePrefix_Passthrough(t *testing.T) {
	provider := NewHeuristicProvider()

	input := "Just a normal system prompt without template prefix"
	resp, err := provider.Complete(context.Background(), Prompt{
		System: "You are a helpful assistant",
		User:   input,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != input {
		t.Errorf("expected passthrough, got %q, want %q", resp.Text, input)
	}
}

func TestHeuristicProvider_EmptyPrompt(t *testing.T) {
	provider := NewHeuristicProvider()

	resp, err := provider.Complete(context.Background(), Prompt{
		System: "",
		User:   "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "" {
		t.Errorf("expected empty text, got %q", resp.Text)
	}
	if resp.Metadata == nil {
		t.Error("metadata should not be nil even for empty prompt")
	}
}
