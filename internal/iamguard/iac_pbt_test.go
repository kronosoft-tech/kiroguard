package iamguard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luiferdev/kiroguard/internal/rpc"
	"pgregory.net/rapid"
)

// TestProperty_IaCWildcardDetection verifies wildcard detection finds all
// Action:* and Resource:* statements in generated IaC content.
func TestProperty_IaCWildcardDetection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		starType := rapid.SampledFrom([]string{"Action", "Resource"}).Draw(t, "starType")
		format := rapid.SampledFrom([]string{"json", "yaml", "tf"}).Draw(t, "format")

		var content string
		var ext string
		switch format {
		case "json":
			ext = ".json"
			content = `{"` + starType + `": "*"}`
		case "yaml":
			ext = ".yaml"
			content = starType + `: "*"`
		case "tf":
			ext = ".tf"
			content = starType + ` = "*"`
		}

		dir, err := os.MkdirTemp("", "rapid-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		if err := os.WriteFile(filepath.Join(dir, "policy"+ext), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		wildcards, err := ScanIACForWildcards(dir, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(wildcards) < 1 {
			t.Fatalf("expected >=1 wildcard for %s=* in %s format, got 0", starType, format)
		}
	})
}

// TestProperty_LLMPolicyBestEffort verifies that LLM errors never block
// the initial response and no notifications leak on failure.
func TestProperty_LLMPolicyBestEffort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		src := `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
}
`
		dir, err := os.MkdirTemp("", "rapid-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}

		mockErr := rapid.SampledFrom([]error{
			errors.New("bedrock unavailable"),
			errors.New("timeout"),
			errors.New("rate limited"),
		}).Draw(t, "llmError")

		mock := &mockLLMBackend{err: mockErr}
		notifier := &mockNotifier{}
		handler := NewIAMGuardHandler(mock)
		handler.SetNotifier(notifier)

		input := IAMGuardInput{DirectoryPath: dir}
		params, _ := json.Marshal(input)
		ctx := rpc.WithClientID(context.Background(), "sess-pbt")

		result, err := handler.Handle(ctx, params)
		if err != nil {
			t.Fatalf("Handle() error: %v", err)
		}

		output := result.(*IAMGuardOutput)
		if len(output.Actions) == 0 {
			t.Fatal("expected actions in response")
		}
		if output.RequestID == "" {
			t.Fatal("expected request_id even when LLM will fail")
		}

		handler.waitBackground()

		if notifier.count() != 0 {
			t.Errorf("expected 0 notifications on LLM error, got %d", notifier.count())
		}
	})
}
