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
	Transport   TransportConfig   `yaml:"transport"`
	LLM         LLMConfig         `yaml:"llm"`
	EnvGuard    EnvGuardConfig    `yaml:"envguard"`
	FinOps      FinOpsConfig      `yaml:"finops"`
	CleanArch   CleanArchConfig   `yaml:"cleanarch"`
	VulnScanner VulnScannerConfig `yaml:"vulnscanner"`
	IAMGuard    IAMGuardConfig    `yaml:"iamguard"`
	LambdaGuard LambdaGuardConfig `yaml:"lambdaguard"`
}

// VulnScannerConfig configures the Vuln-Scanner module.
type VulnScannerConfig struct {
	EnrichTimeoutMs   int `yaml:"enrich_timeout_ms"`           // per-LLM-call deadline, default 1500
	MaxConcurrent     int `yaml:"max_concurrent"`              // GLOBAL max concurrent LLM calls, default 5
	MaxPerRequest     int `yaml:"max_enrichments_per_request"` // per-request enrichment cap, default 5
	MetricsIntervalMs int `yaml:"metrics_interval_ms"`         // periodic metrics report cadence, default 60000
}

// TransportConfig configures the communication transport.
type TransportConfig struct {
	Type       string   `yaml:"type"`        // "stdio" | "sse"
	Port       int      `yaml:"port"`        // default: 3000
	AuthToken  string   `yaml:"auth_token"`  // optional: single bearer token required on SSE endpoints (empty = open)
	AuthTokens []string `yaml:"auth_tokens"` // optional: multiple accepted tokens (enables rotation); merged with auth_token
}

// LLMConfig configures the LLM backend.
type LLMConfig struct {
	Provider string `yaml:"provider"` // "bedrock" | "heuristic"
	ModelID  string `yaml:"model_id"` // default: "anthropic.claude-3-sonnet-20240229-v1:0"
	Region   string `yaml:"region"`   // default: "us-east-1"
}

// EnvGuardConfig configures the Env-Guard secrets module.
type EnvGuardConfig struct {
	IgnoreFile        string  `yaml:"ignore_file"`         // default: ".envguardignore"
	MigrationTarget   string  `yaml:"migration_target"`    // "secrets_manager" | "ssm"
	SSMPrefix         string  `yaml:"ssm_prefix"`          // default: "/kiroguard/"
	WorkerCount       int     `yaml:"worker_count"`        // max concurrent migration workers (default: 5)
	RateLimit         float64 `yaml:"rate_limit"`          // AWS API calls per second (default: 10.0)
	RateBurst         int     `yaml:"rate_burst"`          // burst size for rate limiter (default: 5)
	MetricsIntervalMs int     `yaml:"metrics_interval_ms"` // periodic metrics report cadence, default 60000
}

// FinOpsConfig configures the FinOps Guardrail module.
type FinOpsConfig struct {
	DefaultRPH int `yaml:"default_requests_per_hour"` // default: 1000
}

// IAMGuardConfig configures the IAM-Guard module.
type IAMGuardConfig struct {
	EnrichTimeoutMs   int `yaml:"enrich_timeout_ms"`   // per-LLM-call deadline, default 5000
	ScanTimeoutMs     int `yaml:"scan_timeout_ms"`     // AST + IaC scan deadline, default 10000
	MaxFileSizeMb     int `yaml:"max_file_size_mb"`    // max IaC file size, default 5
	MaxConcurrent     int `yaml:"max_concurrent"`      // GLOBAL max concurrent LLM calls, default 3
	MetricsIntervalMs int `yaml:"metrics_interval_ms"` // periodic metrics report cadence, default 60000
}

// LambdaGuardConfig configures the LambdaGuard module.
type LambdaGuardConfig struct {
	SeverityThreshold string `yaml:"severity_threshold"` // default: "low"
	MaxFileSizeMb     int    `yaml:"max_file_size_mb"`   // max IaC file to parse, default 5
	ScanTimeoutMs     int    `yaml:"scan_timeout_ms"`    // full scan deadline, default 15000
	MetricsIntervalMs int    `yaml:"metrics_interval_ms"` // periodic metrics report cadence, default 60000
}

// CleanArchConfig configures the Clean-Arch module.
type CleanArchConfig struct {
	RulesFile                string `yaml:"rules_file"`                  // default: ".cleanarch.yaml"
	TimeoutMs                int    `yaml:"timeout_ms"`                  // AST scan deadline, default 3000
	EnrichTimeoutMs          int    `yaml:"enrich_timeout_ms"`           // per-LLM-call deadline, default 1500
	MaxConcurrent            int    `yaml:"max_concurrent"`              // GLOBAL max concurrent LLM calls, default 5
	MaxEnrichmentsPerRequest int    `yaml:"max_enrichments_per_request"` // per-request enrichment cap, default 25
	MetricsIntervalMs        int    `yaml:"metrics_interval_ms"`         // periodic metrics report cadence, default 60000
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

	// envguard.worker_count
	if cfg.EnvGuard.WorkerCount < 1 {
		errs = append(errs, "envguard.worker_count: must be greater than 0")
	}

	// envguard.rate_limit
	if cfg.EnvGuard.RateLimit <= 0 {
		errs = append(errs, "envguard.rate_limit: must be greater than 0")
	}

	// envguard.rate_burst
	if cfg.EnvGuard.RateBurst < 1 {
		errs = append(errs, "envguard.rate_burst: must be greater than 0")
	}

	// iamguard.enrich_timeout_ms
	if cfg.IAMGuard.EnrichTimeoutMs < 1 {
		errs = append(errs, "iamguard.enrich_timeout_ms: must be greater than 0")
	}

	// iamguard.scan_timeout_ms
	if cfg.IAMGuard.ScanTimeoutMs < 1 {
		errs = append(errs, "iamguard.scan_timeout_ms: must be greater than 0")
	}

	// iamguard.max_file_size_mb
	if cfg.IAMGuard.MaxFileSizeMb < 1 {
		errs = append(errs, "iamguard.max_file_size_mb: must be greater than 0")
	}

	// iamguard.max_concurrent
	if cfg.IAMGuard.MaxConcurrent < 1 {
		errs = append(errs, "iamguard.max_concurrent: must be greater than 0")
	}

	// lambdaguard.severity_threshold
	if cfg.LambdaGuard.SeverityThreshold != "" {
		switch cfg.LambdaGuard.SeverityThreshold {
		case "low", "medium", "high", "critical":
		default:
			errs = append(errs, "lambdaguard.severity_threshold: must be one of: low, medium, high, critical")
		}
	}

	// lambdaguard.max_file_size_mb
	if cfg.LambdaGuard.MaxFileSizeMb < 1 {
		errs = append(errs, "lambdaguard.max_file_size_mb: must be greater than 0")
	}

	// lambdaguard.scan_timeout_ms
	if cfg.LambdaGuard.ScanTimeoutMs < 1 {
		errs = append(errs, "lambdaguard.scan_timeout_ms: must be greater than 0")
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed: %s", strings.Join(errs, "; "))
	}

	return nil
}
