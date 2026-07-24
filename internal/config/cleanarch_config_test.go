package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_CleanArchHardeningKnobs(t *testing.T) {
	cfg := Default()

	if cfg.CleanArch.TimeoutMs != 3000 {
		t.Errorf("CleanArch.TimeoutMs = %d, want 3000", cfg.CleanArch.TimeoutMs)
	}
	if cfg.CleanArch.EnrichTimeoutMs != 1500 {
		t.Errorf("CleanArch.EnrichTimeoutMs = %d, want 1500", cfg.CleanArch.EnrichTimeoutMs)
	}
	if cfg.CleanArch.MaxConcurrent != 5 {
		t.Errorf("CleanArch.MaxConcurrent = %d, want 5", cfg.CleanArch.MaxConcurrent)
	}
	if cfg.CleanArch.MaxEnrichmentsPerRequest != 25 {
		t.Errorf("CleanArch.MaxEnrichmentsPerRequest = %d, want 25", cfg.CleanArch.MaxEnrichmentsPerRequest)
	}
}

func TestLoad_CleanArchHardeningKnobsOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `cleanarch:
  timeout_ms: 5000
  enrich_timeout_ms: 800
  max_concurrent: 12
  max_enrichments_per_request: 50
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.CleanArch.TimeoutMs != 5000 {
		t.Errorf("TimeoutMs = %d, want 5000", cfg.CleanArch.TimeoutMs)
	}
	if cfg.CleanArch.EnrichTimeoutMs != 800 {
		t.Errorf("EnrichTimeoutMs = %d, want 800", cfg.CleanArch.EnrichTimeoutMs)
	}
	if cfg.CleanArch.MaxConcurrent != 12 {
		t.Errorf("MaxConcurrent = %d, want 12", cfg.CleanArch.MaxConcurrent)
	}
	if cfg.CleanArch.MaxEnrichmentsPerRequest != 50 {
		t.Errorf("MaxEnrichmentsPerRequest = %d, want 50", cfg.CleanArch.MaxEnrichmentsPerRequest)
	}
}
