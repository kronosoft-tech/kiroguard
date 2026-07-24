package iamguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_SDKCallDetectionCompleteness verifies that ALL SDK calls
// in generated Go source files are detected.
func TestProperty_SDKCallDetectionCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		svc := rapid.StringMatching(`[a-z]{2,10}`).Draw(t, "service")
		nMethods := rapid.IntRange(1, 8).Draw(t, "nMethods")
		methods := make([]string, nMethods)
		for i := range methods {
			methods[i] = rapid.StringMatching(`[A-Z][a-zA-Z]{2,20}`).Draw(t, fmt.Sprintf("method_%d", i))
		}

		var stmts []string
		expectedActions := make(map[string]int)
		for _, m := range methods {
			stmts = append(stmts, fmt.Sprintf("\tclient.%s(ctx, nil)", m))
			expectedActions[fmt.Sprintf("%s:%s", svc, m)] = 1
		}

		src := fmt.Sprintf(`package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/%s"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := %s.NewFromConfig(cfg)
%s
}
`, svc, svc, strings.Join(stmts, "\n"))

		dir, err := os.MkdirTemp("", "rapid-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}

		actions, _, err := AnalyzeGoSDKCalls(dir)
		if err != nil {
			t.Fatal(err)
		}

		if len(actions) != len(methods) {
			t.Fatalf("expected %d actions, got %d: %+v", len(methods), len(actions), actions)
		}

		for _, a := range actions {
			if _, ok := expectedActions[a.Action]; !ok {
				t.Errorf("unexpected action %q", a.Action)
			}
			if a.Count != 1 {
				t.Errorf("action %s count = %d, want 1", a.Action, a.Count)
			}
		}
	})
}

// TestProperty_IAMActionMapping verifies iamAction produces correct format.
func TestProperty_IAMActionMapping(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		svc := rapid.StringMatching(`[a-z]{2,10}`).Draw(t, "service")
		method := rapid.StringMatching(`[A-Z][a-zA-Z]{2,30}`).Draw(t, "method")

		action := iamAction(svc, method)
		expected := svc + ":" + method
		if action != expected {
			t.Fatalf("iamAction(%q, %q) = %q, want %q", svc, method, action, expected)
		}
	})
}

// TestProperty_SDKCallDeduplication verifies deduplication counts are correct.
func TestProperty_SDKCallDeduplication(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.IntRange(2, 10).Draw(t, "count")

		var calls []string
		for i := 0; i < count; i++ {
			calls = append(calls, "\tclient.GetObject(ctx, nil)")
		}

		src := fmt.Sprintf(`package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
%s
}
`, strings.Join(calls, "\n"))

		dir, err := os.MkdirTemp("", "rapid-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)

		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}

		actions, _, err := AnalyzeGoSDKCalls(dir)
		if err != nil {
			t.Fatal(err)
		}

		if len(actions) != 1 {
			t.Fatalf("expected 1 deduplicated action, got %d", len(actions))
		}
		if actions[0].Action != "s3:GetObject" {
			t.Errorf("action = %q, want s3:GetObject", actions[0].Action)
		}
		if actions[0].Count != count {
			t.Errorf("count = %d, want %d", actions[0].Count, count)
		}
	})
}
