package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault_ReturnsExpectedValues(t *testing.T) {
	cfg := Default()

	if cfg.Transport.Type != "stdio" {
		t.Errorf("Transport.Type = %q, want %q", cfg.Transport.Type, "stdio")
	}
	if cfg.Transport.Port != 3000 {
		t.Errorf("Transport.Port = %d, want %d", cfg.Transport.Port, 3000)
	}
	if cfg.LLM.Provider != "bedrock" {
		t.Errorf("LLM.Provider = %q, want %q", cfg.LLM.Provider, "bedrock")
	}
	if cfg.LLM.ModelID != "anthropic.claude-3-sonnet-20240229-v1:0" {
		t.Errorf("LLM.ModelID = %q, want %q", cfg.LLM.ModelID, "anthropic.claude-3-sonnet-20240229-v1:0")
	}
	if cfg.LLM.Region != "us-east-1" {
		t.Errorf("LLM.Region = %q, want %q", cfg.LLM.Region, "us-east-1")
	}
	if cfg.EnvGuard.IgnoreFile != ".envguardignore" {
		t.Errorf("EnvGuard.IgnoreFile = %q, want %q", cfg.EnvGuard.IgnoreFile, ".envguardignore")
	}
	if cfg.EnvGuard.MigrationTarget != "secrets_manager" {
		t.Errorf("EnvGuard.MigrationTarget = %q, want %q", cfg.EnvGuard.MigrationTarget, "secrets_manager")
	}
	if cfg.EnvGuard.SSMPrefix != "/kiroguard/" {
		t.Errorf("EnvGuard.SSMPrefix = %q, want %q", cfg.EnvGuard.SSMPrefix, "/kiroguard/")
	}
	if cfg.FinOps.DefaultRPH != 1000 {
		t.Errorf("FinOps.DefaultRPH = %d, want %d", cfg.FinOps.DefaultRPH, 1000)
	}
	if cfg.CleanArch.RulesFile != ".cleanarch.yaml" {
		t.Errorf("CleanArch.RulesFile = %q, want %q", cfg.CleanArch.RulesFile, ".cleanarch.yaml")
	}
}

func TestLoad_EmptyPath_ReturnsDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") returned error: %v", err)
	}

	want := Default()
	if *cfg != *want {
		t.Errorf("Load(\"\") returned different config than Default()")
	}
}

func TestLoad_ValidYAML(t *testing.T) {
	content := `
transport:
  type: sse
  port: 8080
llm:
  provider: heuristic
  model_id: custom-model
  region: eu-west-1
envguard:
  ignore_file: .myignore
  migration_target: ssm
  ssm_prefix: /myapp/
finops:
  default_requests_per_hour: 500
cleanarch:
  rules_file: arch-rules.yaml
`
	path := writeTestFile(t, "config.yaml", content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", path, err)
	}

	if cfg.Transport.Type != "sse" {
		t.Errorf("Transport.Type = %q, want %q", cfg.Transport.Type, "sse")
	}
	if cfg.Transport.Port != 8080 {
		t.Errorf("Transport.Port = %d, want %d", cfg.Transport.Port, 8080)
	}
	if cfg.LLM.Provider != "heuristic" {
		t.Errorf("LLM.Provider = %q, want %q", cfg.LLM.Provider, "heuristic")
	}
	if cfg.LLM.ModelID != "custom-model" {
		t.Errorf("LLM.ModelID = %q, want %q", cfg.LLM.ModelID, "custom-model")
	}
	if cfg.LLM.Region != "eu-west-1" {
		t.Errorf("LLM.Region = %q, want %q", cfg.LLM.Region, "eu-west-1")
	}
	if cfg.EnvGuard.IgnoreFile != ".myignore" {
		t.Errorf("EnvGuard.IgnoreFile = %q, want %q", cfg.EnvGuard.IgnoreFile, ".myignore")
	}
	if cfg.EnvGuard.MigrationTarget != "ssm" {
		t.Errorf("EnvGuard.MigrationTarget = %q, want %q", cfg.EnvGuard.MigrationTarget, "ssm")
	}
	if cfg.EnvGuard.SSMPrefix != "/myapp/" {
		t.Errorf("EnvGuard.SSMPrefix = %q, want %q", cfg.EnvGuard.SSMPrefix, "/myapp/")
	}
	if cfg.FinOps.DefaultRPH != 500 {
		t.Errorf("FinOps.DefaultRPH = %d, want %d", cfg.FinOps.DefaultRPH, 500)
	}
	if cfg.CleanArch.RulesFile != "arch-rules.yaml" {
		t.Errorf("CleanArch.RulesFile = %q, want %q", cfg.CleanArch.RulesFile, "arch-rules.yaml")
	}
}

func TestLoad_PartialYAML_MergesWithDefaults(t *testing.T) {
	content := `
transport:
  port: 9090
`
	path := writeTestFile(t, "partial.yaml", content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", path, err)
	}

	// Overridden value
	if cfg.Transport.Port != 9090 {
		t.Errorf("Transport.Port = %d, want %d", cfg.Transport.Port, 9090)
	}
	// Default values retained
	if cfg.Transport.Type != "stdio" {
		t.Errorf("Transport.Type = %q, want %q (default)", cfg.Transport.Type, "stdio")
	}
	if cfg.LLM.Provider != "bedrock" {
		t.Errorf("LLM.Provider = %q, want %q (default)", cfg.LLM.Provider, "bedrock")
	}
}

func TestLoad_MissingFile_ReturnsError(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("Load with nonexistent path should return an error")
	}
	if !strings.Contains(err.Error(), "reading config file") {
		t.Errorf("error = %q, want it to contain 'reading config file'", err.Error())
	}
}

func TestLoad_InvalidTransportType(t *testing.T) {
	content := `
transport:
  type: grpc
`
	path := writeTestFile(t, "bad_transport.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid transport.type")
	}
	if !strings.Contains(err.Error(), "transport.type") {
		t.Errorf("error = %q, want it to contain field name 'transport.type'", err.Error())
	}
}

func TestLoad_InvalidTransportPort(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"port zero", "transport:\n  port: 0\n"},
		{"port negative", "transport:\n  port: -1\n"},
		{"port too high", "transport:\n  port: 70000\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, "bad_port.yaml", tt.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected validation error for invalid transport.port")
			}
			if !strings.Contains(err.Error(), "transport.port") {
				t.Errorf("error = %q, want it to contain field name 'transport.port'", err.Error())
			}
		})
	}
}

func TestLoad_InvalidLLMProvider(t *testing.T) {
	content := `
llm:
  provider: openai
`
	path := writeTestFile(t, "bad_llm.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid llm.provider")
	}
	if !strings.Contains(err.Error(), "llm.provider") {
		t.Errorf("error = %q, want it to contain field name 'llm.provider'", err.Error())
	}
}

func TestLoad_InvalidFinOpsRPH(t *testing.T) {
	content := `
finops:
  default_requests_per_hour: 0
`
	path := writeTestFile(t, "bad_finops.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid finops.default_requests_per_hour")
	}
	if !strings.Contains(err.Error(), "finops.default_requests_per_hour") {
		t.Errorf("error = %q, want it to contain field name 'finops.default_requests_per_hour'", err.Error())
	}
}

func TestLoad_InvalidMigrationTarget(t *testing.T) {
	content := `
envguard:
  migration_target: vault
`
	path := writeTestFile(t, "bad_envguard.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for invalid envguard.migration_target")
	}
	if !strings.Contains(err.Error(), "envguard.migration_target") {
		t.Errorf("error = %q, want it to contain field name 'envguard.migration_target'", err.Error())
	}
}

func TestLoad_MultipleValidationErrors(t *testing.T) {
	content := `
transport:
  type: grpc
  port: 0
llm:
  provider: openai
`
	path := writeTestFile(t, "multi_errors.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for multiple invalid fields")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "transport.type") {
		t.Errorf("error should mention transport.type, got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "transport.port") {
		t.Errorf("error should mention transport.port, got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "llm.provider") {
		t.Errorf("error should mention llm.provider, got: %q", errMsg)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	content := `{{{invalid yaml`
	path := writeTestFile(t, "invalid.yaml", content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if !strings.Contains(err.Error(), "parsing config file") {
		t.Errorf("error = %q, want it to contain 'parsing config file'", err.Error())
	}
}

// writeTestFile creates a temporary file with the given content and returns its path.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}
