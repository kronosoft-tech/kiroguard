package lambdaguard

import "testing"

func TestScanEnvVars_AWSKey(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"DB_PASSWORD": "AKIA1234567890123456",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for AWS key")
	}
	if findings[0].CheckID != "AWS_ACCESS_KEY" {
		t.Errorf("CheckID = %q, want AWS_ACCESS_KEY", findings[0].CheckID)
	}
	if findings[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
	if findings[0].CurrentValue != "****" {
		t.Errorf("CurrentValue = %q, want ****", findings[0].CurrentValue)
	}
}

func TestScanEnvVars_Email(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"CONTACT": "user@example.com",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for email")
	}
	if findings[0].CheckID != "EMAIL" {
		t.Errorf("CheckID = %q, want EMAIL", findings[0].CheckID)
	}
	if findings[0].Severity != "low" {
		t.Errorf("Severity = %q, want low", findings[0].Severity)
	}
}

func TestScanEnvVars_SecretsManagerRef(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"DB_PASSWORD": "{{resolve:secretsmanager:my-secret:SecretString:password}}",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 (dynamic ref should be skipped)", len(findings))
	}
}

func TestScanEnvVars_HighEntropy(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"API_TOKEN": "aB3dE5fG7hI9kL1mN2oP4qR6sT8uV0wX2yZ4",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for high entropy value")
	}
	if findings[0].CheckID != "HIGH_ENTROPY" {
		t.Errorf("CheckID = %q, want HIGH_ENTROPY", findings[0].CheckID)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
}

func TestScanEnvVars_NoSecrets(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"DB_HOST": "localhost",
			"DB_PORT": "5432",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanEnvVars_EmptyEnv(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment:  map[string]string{},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScanEnvVars_ValueRedacted(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		Environment: map[string]string{
			"SECRET": "AKIA9999999999999999",
		},
	}

	findings := ScanEnvVars(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].CurrentValue != "****" {
		t.Errorf("CurrentValue = %q, want **** (redacted)", findings[0].CurrentValue)
	}
}
