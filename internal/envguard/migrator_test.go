package envguard

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// --- Mock clients ---

type mockSMClient struct {
	createSecretFn func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

func (m *mockSMClient) CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return m.createSecretFn(ctx, params, optFns...)
}

type mockSSMClient struct {
	putParameterFn func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

func (m *mockSSMClient) PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	return m.putParameterFn(ctx, params, optFns...)
}

// --- Tests ---

func TestNewMigrator_UnsupportedTarget(t *testing.T) {
	ctx := context.Background()
	_, err := NewMigrator(ctx, MigratorConfig{Target: "invalid_target", Region: "us-east-1"})
	if err == nil {
		t.Fatal("expected error for unsupported migration target, got nil")
	}
	if !contains(err.Error(), "unsupported migration target") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrate_SecretsManager_Success(t *testing.T) {
	expectedARN := "arn:aws:secretsmanager:us-east-1:123456789012:secret:kiroguard-src-main-go-aws-key-AbCdEf"

	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			// Verify input
			if params.Name == nil || *params.Name == "" {
				t.Error("expected non-empty secret name")
			}
			if params.SecretString == nil || *params.SecretString != "AKIAIOSFODNN7EXAMPLE" {
				t.Errorf("expected value 'AKIAIOSFODNN7EXAMPLE', got %v", params.SecretString)
			}
			return &secretsmanager.CreateSecretOutput{
				ARN: aws.String(expectedARN),
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	secret := SecretFinding{
		LineNumber:  10,
		FilePath:    "src/main.go",
		SecretType:  "aws_key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
	}

	arn, err := migrator.Migrate(context.Background(), secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if arn != expectedARN {
		t.Errorf("expected ARN %q, got %q", expectedARN, arn)
	}
}

func TestMigrate_SSM_Success(t *testing.T) {
	ssmClient := &mockSSMClient{
		putParameterFn: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			// Verify input
			if params.Name == nil || *params.Name == "" {
				t.Error("expected non-empty parameter name")
			}
			if params.Type != ssmtypes.ParameterTypeSecureString {
				t.Errorf("expected type SecureString, got %v", params.Type)
			}
			if params.Value == nil || *params.Value != "sk-secret123" {
				t.Errorf("expected value 'sk-secret123', got %v", params.Value)
			}
			// Verify name includes prefix
			if params.Name != nil && *params.Name != "/kiroguard/kiroguard-config-env-api-token" {
				t.Errorf("unexpected parameter name: %q", *params.Name)
			}
			return &ssm.PutParameterOutput{
				Version: 1,
			}, nil
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "ssm", SSMPrefix: "/kiroguard/", Region: "us-east-1"},
		nil,
		ssmClient,
	)

	secret := SecretFinding{
		LineNumber:  5,
		FilePath:    "config/.env",
		SecretType:  "api_token",
		SecretValue: "sk-secret123",
	}

	arn, err := migrator.Migrate(context.Background(), secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedARN := "arn:aws:ssm:us-east-1::parameter/kiroguard/kiroguard-config-env-api-token"
	if arn != expectedARN {
		t.Errorf("expected ARN %q, got %q", expectedARN, arn)
	}
}

func TestMigrate_AWSError_Propagated(t *testing.T) {
	awsErr := fmt.Errorf("AccessDeniedException: not authorized")

	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			return nil, awsErr
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "AccessDeniedException") {
		t.Errorf("expected error to contain 'AccessDeniedException', got: %v", err)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		secretType string
		want       string
	}{
		{
			name:       "simple path and type",
			filePath:   "main.go",
			secretType: "aws_key",
			want:       "kiroguard-main-go-aws-key",
		},
		{
			name:       "path with slashes",
			filePath:   "src/config/secrets.go",
			secretType: "api_token",
			want:       "kiroguard-src-config-secrets-go-api-token",
		},
		{
			name:       "path with special characters",
			filePath:   "config/.env.production",
			secretType: "database_dsn",
			want:       "kiroguard-config-env-production-database-dsn",
		},
		{
			name:       "path with spaces",
			filePath:   "my folder/file.go",
			secretType: "private key",
			want:       "kiroguard-my-folder-file-go-private-key",
		},
		{
			name:       "consecutive special chars",
			filePath:   "src///main.go",
			secretType: "jwt",
			want:       "kiroguard-src-main-go-jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeName(tt.filePath, tt.secretType)
			if got != tt.want {
				t.Errorf("sanitizeName(%q, %q) = %q, want %q", tt.filePath, tt.secretType, got, tt.want)
			}
		})
	}
}

func TestMigrate_Timeout_Enforced(t *testing.T) {
	// Mock client that sleeps longer than the 10-second timeout.
	// We use a much shorter parent context deadline to make the test fast.
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			// Block until context is cancelled (simulating slow AWS call)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		smClient,
		nil,
	)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
	}

	// Use a parent context with a short deadline to speed up the test.
	// The migrator internally creates a 10s timeout, but our parent context
	// cancels sooner, which should propagate.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := migrator.Migrate(ctx, secret)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !contains(err.Error(), "context deadline exceeded") && !contains(err.Error(), "context canceled") {
		t.Errorf("expected context error, got: %v", err)
	}
	// Verify it didn't block for longer than expected.
	if elapsed > 1*time.Second {
		t.Errorf("expected fast timeout, but took %v", elapsed)
	}
}

func TestMigrate_SSM_Error_Propagated(t *testing.T) {
	ssmErr := fmt.Errorf("ParameterAlreadyExists: the parameter already exists")

	ssmClient := &mockSSMClient{
		putParameterFn: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return nil, ssmErr
		},
	}

	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "ssm", SSMPrefix: "/kiroguard/", Region: "us-east-1"},
		nil,
		ssmClient,
	)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "app.go",
		SecretType:  "api_key",
		SecretValue: "key-12345",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !contains(err.Error(), "ParameterAlreadyExists") {
		t.Errorf("expected error to contain 'ParameterAlreadyExists', got: %v", err)
	}
}

func TestMigrate_UnsupportedTarget(t *testing.T) {
	migrator := NewMigratorWithClients(MigratorConfig{Target: "unsupported"}, nil, nil)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "AKIAIOSFODNN7EXAMPLE",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error for unsupported target, got nil")
	}
	if !contains(err.Error(), `unsupported migration target: "unsupported"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrate_SecretsManager_NilARN(t *testing.T) {
	smClient := &mockSMClient{
		createSecretFn: func(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
			return &secretsmanager.CreateSecretOutput{ARN: nil}, nil
		},
	}

	migrator := NewMigratorWithClients(MigratorConfig{Target: "secrets_manager"}, smClient, nil)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "secret123",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error for nil ARN, got nil")
	}
	if !contains(err.Error(), "nil ARN") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrate_SSM_NilOutput(t *testing.T) {
	ssmClient := &mockSSMClient{
		putParameterFn: func(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
			return nil, nil
		},
	}

	migrator := NewMigratorWithClients(MigratorConfig{Target: "ssm", SSMPrefix: "/test/"}, nil, ssmClient)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "secret123",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error for nil SSM output, got nil")
	}
	if !contains(err.Error(), "nil output") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrate_SMClientNotInitialized(t *testing.T) {
	// migrator with target "secrets_manager" but nil smClient
	migrator := NewMigratorWithClients(MigratorConfig{Target: "secrets_manager"}, nil, &mockSSMClient{})

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "secret123",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error for nil SM client, got nil")
	}
	if !contains(err.Error(), "not initialized") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMigrate_SSMClientNotInitialized(t *testing.T) {
	migrator := NewMigratorWithClients(MigratorConfig{Target: "ssm", SSMPrefix: "/test/"}, &mockSMClient{}, nil)

	secret := SecretFinding{
		LineNumber:  1,
		FilePath:    "main.go",
		SecretType:  "aws_key",
		SecretValue: "secret123",
	}

	_, err := migrator.Migrate(context.Background(), secret)
	if err == nil {
		t.Fatal("expected error for nil SSM client, got nil")
	}
	if !contains(err.Error(), "not initialized") {
		t.Errorf("unexpected error: %v", err)
	}
}

// contains checks if substr is in s.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
