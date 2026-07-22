package envguard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/luiferdev/kiroguard/internal/rpc"
	"golang.org/x/time/rate"
)

// --- Helper to create params JSON ---

func makeParams(t *testing.T, input EnvGuardInput) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("failed to marshal input: %v", err)
	}
	return data
}

// --- Tests ---

func TestHandle_EmptyDiff(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	params := makeParams(t, EnvGuardInput{Diff: ""})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output, ok := result.(*EnvGuardOutput)
	if !ok {
		t.Fatalf("expected *EnvGuardOutput, got %T", result)
	}
	if output.Blocked {
		t.Error("expected Blocked=false for empty diff")
	}
	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(output.Findings))
	}
}

func TestHandle_NoSecrets(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
+var greeting = "hello world"
 func main() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if output.Blocked {
		t.Error("expected Blocked=false for clean diff")
	}
	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(output.Findings))
	}
}

func TestHandle_DetectsSecret_NoMigrator(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,3 @@
 package config
+const key = "AKIAIOSFODNN7EXAMPLE"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if !output.Blocked {
		t.Error("expected Blocked=true when secret detected")
	}
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	f := output.Findings[0]
	if f.SecretType != "aws_access_key" {
		t.Errorf("expected secret_type 'aws_access_key', got %q", f.SecretType)
	}
	if f.Replacement == "" {
		t.Error("expected non-empty replacement")
	}
	if f.SecretValue != "" {
		t.Error("expected SecretValue to be cleared in output")
	}
	// Replacement must not contain the original secret
	if strings.Contains(f.Replacement, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("replacement must not contain the original secret value")
	}
	// Should contain env var reference
	if !strings.Contains(f.Replacement, "os.Getenv") {
		t.Error("replacement should contain os.Getenv reference")
	}
	// Message should mention AWS not configured
	if !strings.Contains(output.Message, "migration unavailable") {
		t.Errorf("expected message about migration unavailable, got: %q", output.Message)
	}
}

func TestHandle_DetectsSecret_WithMigrator(t *testing.T) {
	expectedARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:kiroguard-test"

	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *smtypes.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*smtypes.CreateSecretOutput, error) {
			return &smtypes.CreateSecretOutput{
				ARN: aws.String(expectedARN),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/app.go
+++ b/app.go
@@ -1,2 +1,3 @@
 package app
+var apiKey = "sk-abcdefghijklmnopqrstuvwxyz1234"
 func main() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if !output.Blocked {
		t.Error("expected Blocked=true")
	}
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	f := output.Findings[0]
	if f.MigratedARN != expectedARN {
		t.Errorf("expected MigratedARN %q, got %q", expectedARN, f.MigratedARN)
	}
	if f.MigrationErr != "" {
		t.Errorf("expected no migration error, got %q", f.MigrationErr)
	}
	if f.Replacement == "" {
		t.Error("expected non-empty replacement")
	}
	if f.SecretValue != "" {
		t.Error("expected SecretValue to be cleared")
	}
}

func TestHandle_MigratorError_StillBlocked(t *testing.T) {
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *smtypes.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*smtypes.CreateSecretOutput, error) {
			return nil, fmt.Errorf("AccessDeniedException: not authorized")
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/secrets.go
+++ b/secrets.go
@@ -1,2 +1,3 @@
 package secrets
+const awsKey = "AKIAIOSFODNN7EXAMPLE"
 func init() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if !output.Blocked {
		t.Error("expected Blocked=true even when migration fails")
	}
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	f := output.Findings[0]
	if f.MigrationErr == "" {
		t.Error("expected migration error to be set")
	}
	if !strings.Contains(f.MigrationErr, "AccessDeniedException") {
		t.Errorf("expected AccessDeniedException in MigrationErr, got %q", f.MigrationErr)
	}
	if f.MigratedARN != "" {
		t.Errorf("expected empty MigratedARN, got %q", f.MigratedARN)
	}
	// Still gets a replacement suggestion
	if f.Replacement == "" {
		t.Error("expected replacement even when migration fails")
	}
}

func TestHandle_IgnoreFilter(t *testing.T) {
	ignoreContent := `# Ignore test keys
AKIAIOSFODNN7EXAMPLE`

	ignore, err := NewIgnoreParser(ignoreContent)
	if err != nil {
		t.Fatalf("failed to create ignore parser: %v", err)
	}

	handler := NewEnvGuardHandler(NewSecretScanner(), ignore, nil, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/test.go
+++ b/test.go
@@ -1,2 +1,3 @@
 package test
+const key = "AKIAIOSFODNN7EXAMPLE"
 func main() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if output.Blocked {
		t.Error("expected Blocked=false when secret matches ignore pattern")
	}
	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings after filtering, got %d", len(output.Findings))
	}
}

func TestHandle_PartialIgnoreFilter(t *testing.T) {
	// Ignore only AWS keys but not database DSNs.
	// Use a glob pattern with * that matches the AKIA key value.
	ignoreContent := `AKIA*`

	ignore, err := NewIgnoreParser(ignoreContent)
	if err != nil {
		t.Fatalf("failed to create ignore parser: %v", err)
	}

	handler := NewEnvGuardHandler(NewSecretScanner(), ignore, nil, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/multi.go
+++ b/multi.go
@@ -1,2 +1,4 @@
 package multi
+const key = "AKIAIOSFODNN7EXAMPLE"
+const dsn = "postgres://admin:secret@db.host.com:5432/mydb"
 func main() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if !output.Blocked {
		t.Error("expected Blocked=true for DSN that isn't ignored")
	}
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding (DSN only), got %d", len(output.Findings))
	}
	if output.Findings[0].SecretType != "database_dsn" {
		t.Errorf("expected database_dsn finding, got %q", output.Findings[0].SecretType)
	}
}

func TestHandle_InvalidParams(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	// Invalid JSON
	result, err := handler.Handle(context.Background(), json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid params")
	}
	if result != nil {
		t.Errorf("expected nil result on error, got %v", result)
	}
}

func TestHandle_MultipleFindings(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/multi.go
+++ b/multi.go
@@ -1,2 +1,5 @@
 package multi
+const key = "AKIAIOSFODNN7EXAMPLE"
+const dsn = "mysql://root:password@localhost/db"
+const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
 func main() {}
`
	params := makeParams(t, EnvGuardInput{Diff: diff})
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if !output.Blocked {
		t.Error("expected Blocked=true")
	}
	if len(output.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(output.Findings))
	}

	// All findings should have replacements and no secret values
	for i, f := range output.Findings {
		if f.Replacement == "" {
			t.Errorf("finding %d: expected non-empty replacement", i)
		}
		if f.SecretValue != "" {
			t.Errorf("finding %d: expected SecretValue to be cleared", i)
		}
	}
}

func TestHandle_ReplacementDoesNotContainSecret(t *testing.T) {
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://admin:supersecret@db.example.com:5432/prod",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789",
	}

	for _, secret := range secrets {
		diff := fmt.Sprintf("--- a/f.go\n+++ b/f.go\n@@ -1,1 +1,2 @@\n pkg\n+%s\n", secret)
		params := makeParams(t, EnvGuardInput{Diff: diff})
		result, err := handler.Handle(context.Background(), params)
		if err != nil {
			t.Fatalf("unexpected error for secret %q: %v", secret[:10], err)
		}

		output := result.(*EnvGuardOutput)
		for _, f := range output.Findings {
			if strings.Contains(f.Replacement, secret) {
				t.Errorf("replacement contains original secret value %q", secret[:10])
			}
		}
	}
}

func TestSanitizeEnvName(t *testing.T) {
	tests := []struct {
		secretType string
		want       string
	}{
		{"aws_access_key", "KIROGUARD_AWS_ACCESS_KEY"},
		{"generic_api_key", "KIROGUARD_GENERIC_API_KEY"},
		{"database_dsn", "KIROGUARD_DATABASE_DSN"},
		{"private_key", "KIROGUARD_PRIVATE_KEY"},
		{"jwt_token", "KIROGUARD_JWT_TOKEN"},
		{"aws_secret_key", "KIROGUARD_AWS_SECRET_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.secretType, func(t *testing.T) {
			got := sanitizeEnvName(tt.secretType)
			if got != tt.want {
				t.Errorf("sanitizeEnvName(%q) = %q, want %q", tt.secretType, got, tt.want)
			}
		})
	}
}

func TestRegisterEnvGuard(t *testing.T) {
	dispatcher := rpc.NewDispatcher()
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, nil, 5, rate.NewLimiter(rate.Inf, 0))

	RegisterEnvGuard(dispatcher, handler)

	// Verify the handler is registered by dispatching a request
	id := json.RawMessage(`1`)
	params := makeParams(t, EnvGuardInput{Diff: ""})
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "envguard/scan",
		Params:  params,
	}

	resp := dispatcher.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("unexpected error from dispatcher: %v", resp.Error.Message)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify it returns a valid EnvGuardOutput
	var output EnvGuardOutput
	if err := json.Unmarshal(resp.Result, &output); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if output.Blocked {
		t.Error("expected Blocked=false for empty diff")
	}
}

func TestGenerateReplacement(t *testing.T) {
	tests := []struct {
		name    string
		finding SecretFinding
		wantEnv string
	}{
		{
			name: "with migrated ARN",
			finding: SecretFinding{
				SecretType:  "aws_access_key",
				MigratedARN: "arn:aws:secretsmanager:us-east-1:123:secret:test",
			},
			wantEnv: "KIROGUARD_AWS_ACCESS_KEY",
		},
		{
			name: "without migrated ARN",
			finding: SecretFinding{
				SecretType: "database_dsn",
			},
			wantEnv: "KIROGUARD_DATABASE_DSN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateReplacement(tt.finding)
			expected := fmt.Sprintf(`os.Getenv("%s")`, tt.wantEnv)
			if got != expected {
				t.Errorf("generateReplacement() = %q, want %q", got, expected)
			}
		})
	}
}

// --- Concurrency Tests ---

func TestMigrateAll_Concurrent(t *testing.T) {
	// Each migration takes 100ms. With 5 findings and workerCount=5,
	// all should run in parallel, completing in ~100ms total (not 500ms sequential).
	delay := 100 * time.Millisecond
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			time.Sleep(delay)
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:test"),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	// Build a diff with 5 distinct secrets
	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,7 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
+const key4 = "AKIAIOSFODNN7EXAMPL4"
+const key5 = "AKIAIOSFODNN7EXAMPL5"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	start := time.Now()
	result, err := handler.Handle(context.Background(), params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if len(output.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(output.Findings))
	}

	// If sequential, would take 500ms. Parallel with 5 workers should be ~100ms.
	// Allow generous margin for CI flakiness.
	if elapsed >= 400*time.Millisecond {
		t.Errorf("expected parallel execution < 400ms, took %v", elapsed)
	}
}

func TestMigrateAll_WorkerCountBounds(t *testing.T) {
	// Track max concurrent goroutines using atomic counter.
	var active atomic.Int32
	var maxActive atomic.Int32

	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			cur := active.Add(1)
			// Update max if this is a new high watermark
			for {
				old := maxActive.Load()
				if cur <= old {
					break
				}
				if maxActive.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			active.Add(-1)
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:test"),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	// workerCount=2, 5 findings
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 2, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,7 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
+const key4 = "AKIAIOSFODNN7EXAMPL4"
+const key5 = "AKIAIOSFODNN7EXAMPL5"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	_, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if maxActive.Load() > 2 {
		t.Errorf("expected max concurrent goroutines <= 2, got %d", maxActive.Load())
	}
}

func TestMigrateAll_ContextCancellation(t *testing.T) {
	// Each migration takes 200ms. Cancel context after 50ms.
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			select {
			case <-time.After(200 * time.Millisecond):
				return &secretsmanager.CreateSecretOutput{
					ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:test"),
				}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,7 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
+const key4 = "AKIAIOSFODNN7EXAMPL4"
+const key5 = "AKIAIOSFODNN7EXAMPL5"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	var result interface{}
	var handleErr error

	go func() {
		result, handleErr = handler.Handle(ctx, params)
		close(done)
	}()

	// Verify it doesn't hang — should complete within 1 second
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("handler hung after context cancellation")
	}

	if handleErr != nil {
		t.Fatalf("unexpected error: %v", handleErr)
	}

	output := result.(*EnvGuardOutput)
	// At least some findings should have MigrationErr containing "context"
	hasContextErr := false
	for _, f := range output.Findings {
		if strings.Contains(f.MigrationErr, "context") {
			hasContextErr = true
			break
		}
	}
	if !hasContextErr {
		t.Error("expected at least one finding with context-related MigrationErr")
	}
}

func TestMigrateAll_IndependentErrors(t *testing.T) {
	// Fail only on the second secret (index 1 by finding order).
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			// Check SecretString to identify which finding this is
			if params.SecretString != nil && strings.Contains(*params.SecretString, "EXAMPL2") {
				return nil, fmt.Errorf("SimulatedFailure: access denied")
			}
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:ok"),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,5 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if len(output.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(output.Findings))
	}

	// Finding 0: should succeed
	if output.Findings[0].MigrationErr != "" {
		t.Errorf("finding[0]: expected no error, got %q", output.Findings[0].MigrationErr)
	}

	// Finding 1: should fail
	if output.Findings[1].MigrationErr == "" {
		t.Error("finding[1]: expected migration error")
	}
	if !strings.Contains(output.Findings[1].MigrationErr, "SimulatedFailure") {
		t.Errorf("finding[1]: expected SimulatedFailure, got %q", output.Findings[1].MigrationErr)
	}

	// Finding 2: should succeed (not blocked by finding 1's failure)
	if output.Findings[2].MigrationErr != "" {
		t.Errorf("finding[2]: expected no error, got %q", output.Findings[2].MigrationErr)
	}
}

func TestMigrateAll_OrderPreserved(t *testing.T) {
	// Each finding takes a different amount of time, but output order should match input order.
	delays := []time.Duration{80 * time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond, 30 * time.Millisecond, 60 * time.Millisecond}
	callIdx := atomic.Int32{}

	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			// Determine which secret this is by checking SecretString content
			idx := -1
			if params.SecretString != nil {
				val := *params.SecretString
				for i := 1; i <= 5; i++ {
					if strings.Contains(val, fmt.Sprintf("EXAMPL%d", i)) {
						idx = i - 1
						break
					}
				}
			}
			if idx >= 0 && idx < len(delays) {
				time.Sleep(delays[idx])
			}
			callIdx.Add(1)
			arn := fmt.Sprintf("arn:aws:secretsmanager:us-east-1:123:secret:finding-%d", idx)
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String(arn),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 5, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,7 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
+const key4 = "AKIAIOSFODNN7EXAMPL4"
+const key5 = "AKIAIOSFODNN7EXAMPL5"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if len(output.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(output.Findings))
	}

	// Verify that findings are still in order: finding[i] should have the ARN for finding-i
	for i, f := range output.Findings {
		expectedARN := fmt.Sprintf("arn:aws:secretsmanager:us-east-1:123:secret:finding-%d", i)
		if f.MigratedARN != expectedARN {
			t.Errorf("finding[%d]: expected ARN %q, got %q (order not preserved)", i, expectedARN, f.MigratedARN)
		}
	}
}

func TestMigrateAll_SingleWorker(t *testing.T) {
	// WorkerCount=1 means sequential execution. 3 findings × 50ms = >= 150ms total.
	delay := 50 * time.Millisecond
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			time.Sleep(delay)
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String("arn:aws:secretsmanager:us-east-1:123:secret:test"),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	// workerCount=1 — strictly sequential
	handler := NewEnvGuardHandler(NewSecretScanner(), nil, migrator, 1, rate.NewLimiter(rate.Inf, 0))

	diff := `--- a/config.go
+++ b/config.go
@@ -1,2 +1,5 @@
 package config
+const key1 = "AKIAIOSFODNN7EXAMPL1"
+const key2 = "AKIAIOSFODNN7EXAMPL2"
+const key3 = "AKIAIOSFODNN7EXAMPL3"
 var x = 1
`
	params := makeParams(t, EnvGuardInput{Diff: diff})

	start := time.Now()
	result, err := handler.Handle(context.Background(), params)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := result.(*EnvGuardOutput)
	if len(output.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(output.Findings))
	}

	// With 1 worker, 3 secrets × 50ms = at least 150ms
	if elapsed < 150*time.Millisecond {
		t.Errorf("expected sequential execution >= 150ms with 1 worker, took %v", elapsed)
	}
}
