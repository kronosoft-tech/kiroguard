package iamguard

import (
	"os"
	"path/filepath"
	"testing"
)

// --- isAWSSDKImport ---

func TestIsAWSSDKImport_S3(t *testing.T) {
	svc, ok := isAWSSDKImport("github.com/aws/aws-sdk-go-v2/service/s3")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if svc != "s3" {
		t.Fatalf("service = %q, want %q", svc, "s3")
	}
}

func TestIsAWSSDKImport_MultipleServices(t *testing.T) {
	tests := []struct {
		path        string
		wantService string
		wantOK      bool
	}{
		{"github.com/aws/aws-sdk-go-v2/service/s3", "s3", true},
		{"github.com/aws/aws-sdk-go-v2/service/dynamodb", "dynamodb", true},
		{"github.com/aws/aws-sdk-go-v2/service/sqs", "sqs", true},
		{"github.com/aws/aws-sdk-go-v2/service/lambda", "lambda", true},
	}
	for _, tt := range tests {
		svc, ok := isAWSSDKImport(tt.path)
		if ok != tt.wantOK {
			t.Errorf("isAWSSDKImport(%q) ok=%v, want %v", tt.path, ok, tt.wantOK)
		}
		if svc != tt.wantService {
			t.Errorf("isAWSSDKImport(%q) service=%q, want %q", tt.path, svc, tt.wantService)
		}
	}
}

func TestIsAWSSDKImport_NonAWS(t *testing.T) {
	_, ok := isAWSSDKImport("fmt")
	if ok {
		t.Fatal("expected ok=false for stdlib import")
	}
}

func TestIsAWSSDKImport_Core(t *testing.T) {
	_, ok := isAWSSDKImport("github.com/aws/aws-sdk-go-v2/config")
	if ok {
		t.Fatal("expected ok=false for non-service SDK import")
	}
}

// --- iamAction ---

func TestIAMAction_Format(t *testing.T) {
	action := iamAction("s3", "GetObject")
	if action != "s3:GetObject" {
		t.Fatalf("iamAction = %q, want %q", action, "s3:GetObject")
	}
}

// --- writeGoFile helper ---

func writeGoFile(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- AnalyzeGoSDKCalls ---

func TestAnalyzeGoSDKCalls_SingleService(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
	client.PutObject(ctx, nil)
}
`)

	actions, usages, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d: %+v", len(actions), actions)
	}
	actionMap := make(map[string]int)
	for _, a := range actions {
		actionMap[a.Action] = a.Count
	}
	if actionMap["s3:GetObject"] != 1 {
		t.Errorf("s3:GetObject count = %d, want 1", actionMap["s3:GetObject"])
	}
	if actionMap["s3:PutObject"] != 1 {
		t.Errorf("s3:PutObject count = %d, want 1", actionMap["s3:PutObject"])
	}
	if len(usages) != 2 {
		t.Fatalf("expected 2 usages, got %d", len(usages))
	}
}

func TestAnalyzeGoSDKCalls_MultipleServices(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	s3Client := s3.NewFromConfig(cfg)
	s3Client.GetObject(ctx, nil)
	s3Client.PutObject(ctx, nil)

	ddbClient := dynamodb.NewFromConfig(cfg)
	ddbClient.GetItem(ctx, nil)
	ddbClient.PutItem(ctx, nil)

	sqsClient := sqs.NewFromConfig(cfg)
	sqsClient.SendMessage(ctx, nil)
}
`)

	actions, _, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 5 {
		t.Fatalf("expected 5 actions, got %d: %+v", len(actions), actions)
	}
}

func TestAnalyzeGoSDKCalls_NoSDKImports(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`)

	actions, usages, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(actions))
	}
	if len(usages) != 0 {
		t.Fatalf("expected 0 usages, got %d", len(usages))
	}
}

func TestAnalyzeGoSDKCalls_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	actions, usages, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Errorf("expected 0 actions, got %d", len(actions))
	}
	if len(usages) != 0 {
		t.Errorf("expected 0 usages, got %d", len(usages))
	}
}

func TestAnalyzeGoSDKCalls_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "handler_test.go", `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func testStuff() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
}
`)
	writeGoFile(t, dir, "handler.go", `package main

import "fmt"

func main() { fmt.Println("ok") }
`)

	actions, _, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions (test file skipped), got %d", len(actions))
	}
}

func TestAnalyzeGoSDKCalls_SkipsVendorDir(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, filepath.Join(dir, "vendor", "somepkg"), "main.go", `package main

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
`)
	writeGoFile(t, dir, "main.go", `package main

import "fmt"

func main() { fmt.Println("ok") }
`)

	actions, _, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions (vendor skipped), got %d", len(actions))
	}
}

func TestAnalyzeGoSDKCalls_SyntaxErrorSkipsFile(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "broken.go", `package main

import "github.com/aws/aws-sdk-go-v2/service/s3"

func main() {
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
	SYNTAX ERROR HERE
}
`)
	writeGoFile(t, dir, "good.go", `package main

import "fmt"

func main() { fmt.Println("ok") }
`)

	actions, _, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions (broken file skipped), got %d", len(actions))
	}
}

func TestAnalyzeGoSDKCalls_DuplicateCallsDeduped(t *testing.T) {
	dir := t.TempDir()
	writeGoFile(t, dir, "main.go", `package main

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func main() {
	ctx := context.TODO()
	cfg := struct{}{}
	client := s3.NewFromConfig(cfg)
	client.GetObject(ctx, nil)
	client.GetObject(ctx, nil)
	client.GetObject(ctx, nil)
}
`)

	actions, usages, err := AnalyzeGoSDKCalls(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 deduplicated action, got %d: %+v", len(actions), actions)
	}
	if actions[0].Action != "s3:GetObject" {
		t.Errorf("action = %q, want %q", actions[0].Action, "s3:GetObject")
	}
	if actions[0].Count != 3 {
		t.Errorf("count = %d, want 3", actions[0].Count)
	}
	if len(usages) != 3 {
		t.Fatalf("expected 3 usages, got %d", len(usages))
	}
}

func TestAnalyzeGoSDKCalls_NonexistentDir(t *testing.T) {
	_, _, err := AnalyzeGoSDKCalls("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent dir")
	}
}
