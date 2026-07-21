// Package config handles configuration loading and validation for KiroGuard.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for KiroGuard.
type Config struct {
	Transport TransportConfig `yaml:"transport"`
	LLM       LLMConfig       `yaml:"llm"`
	EnvGuard  EnvGuardConfig  `yaml:"envguard"`
	FinOps    FinOpsConfig    `yaml:"finops"`
	CleanArch CleanArchConfig `yaml:"cleanarch"`
}

// TransportConfig configures the communication transport.
type TransportConfig struct {
	Type string `yaml:"type"` // "stdio" | "sse"
	Port int    `yaml:"port"` // default: 3000
}

// LLMConfig configures the LLM backend.
type LLMConfig struct {
	Provider string `yaml:"provider"` // "bedrock" | "heuristic"
	ModelID  string `yaml:"model_id"` // default: "anthropic.claude-3-sonnet-20240229-v1:0"
	Region   string `yaml:"region"`   // default: "us-east-1"
}

// EnvGuardConfig configures the Env-Guard secrets module.
type EnvGuardConfig struct {
	IgnoreFile      string `yaml:"ignore_file"`      // default: ".envguardignore"
	MigrationTarget string `yaml:"migration_target"` // "secrets_manager" | "ssm"
	SSMPrefix       string `yaml:"ssm_prefix"`       // default: "/kiroguard/"
}

// FinOpsConfig configures the FinOps Guardrail module.
type FinOpsConfig struct {
	DefaultRPH int `yaml:"default_requests_per_hour"` // default: 1000
}

// CleanArchConfig configures the Clean-Arch module.
type CleanArchConfig struct {
	RulesFile string `yaml:"rules_file"` // default: ".cleanarch.yaml"
}

// Load reads a YAML configuration file from the given path and returns a
// validated Config. If path is empty, it returns the default configuration.
// Loaded values override defaults; unset fields retain their default values.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := validate(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks all config fields and returns a descriptive error identifying
// the specific field that is invalid.
func validate(cfg *Config) error {
	var errs []string

	// transport.type
	if cfg.Transport.Type != "" {
		if cfg.Transport.Type != "stdio" && cfg.Transport.Type != "sse" {
			errs = append(errs, "transport.type: must be 'stdio' or 'sse'")
		}
	}

	// transport.port
	if cfg.Transport.Port < 1 || cfg.Transport.Port > 65535 {
		errs = append(errs, "transport.port: must be between 1 and 65535")
	}

	// llm.provider
	if cfg.LLM.Provider != "" {
		if cfg.LLM.Provider != "bedrock" && cfg.LLM.Provider != "heuristic" {
			errs = append(errs, "llm.provider: must be 'bedrock' or 'heuristic'")
		}
	}

	// finops.default_requests_per_hour
	if cfg.FinOps.DefaultRPH < 1 {
		errs = append(errs, "finops.default_requests_per_hour: must be greater than 0")
	}

	// envguard.migration_target
	if cfg.EnvGuard.MigrationTarget != "" {
		if cfg.EnvGuard.MigrationTarget != "secrets_manager" && cfg.EnvGuard.MigrationTarget != "ssm" {
			errs = append(errs, "envguard.migration_target: must be 'secrets_manager' or 'ssm'")
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}
