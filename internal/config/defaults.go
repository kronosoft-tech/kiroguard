package config

// Default returns a Config populated with sensible default values for all fields.
func Default() *Config {
	return &Config{
		Transport: TransportConfig{
			Type: "stdio",
			Port: 3000,
		},
		LLM: LLMConfig{
			Provider: "bedrock",
			ModelID:  "anthropic.claude-3-sonnet-20240229-v1:0",
			Region:   "us-east-1",
		},
		EnvGuard: EnvGuardConfig{
			IgnoreFile:      ".envguardignore",
			MigrationTarget: "secrets_manager",
			SSMPrefix:       "/kiroguard/",
			WorkerCount:     5,
			RateLimit:       10.0,
			RateBurst:       5,
		},
		FinOps: FinOpsConfig{
			DefaultRPH: 1000,
		},
		CleanArch: CleanArchConfig{
			RulesFile: ".cleanarch.yaml",
		},
	}
}
