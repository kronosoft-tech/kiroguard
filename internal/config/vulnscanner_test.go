package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_VulnScanner(t *testing.T) {
	cfg := Default()
	if cfg.VulnScanner.EnrichTimeoutMs != 1500 {
		t.Errorf("EnrichTimeoutMs = %d, want 1500", cfg.VulnScanner.EnrichTimeoutMs)
	}
	if cfg.VulnScanner.MaxConcurrent != 5 {
		t.Errorf("MaxConcurrent = %d, want 5", cfg.VulnScanner.MaxConcurrent)
	}
	if cfg.VulnScanner.MaxPerRequest != 5 {
		t.Errorf("MaxPerRequest = %d, want 5", cfg.VulnScanner.MaxPerRequest)
	}
	if cfg.VulnScanner.MetricsIntervalMs != 60000 {
		t.Errorf("MetricsIntervalMs = %d, want 60000", cfg.VulnScanner.MetricsIntervalMs)
	}
}

func TestLoad_VulnScannerOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "vulnscanner:\n  enrich_timeout_ms: 800\n  max_concurrent: 8\n  max_enrichments_per_request: 10\n  metrics_interval_ms: 30000\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.VulnScanner.EnrichTimeoutMs != 800 {
		t.Errorf("EnrichTimeoutMs = %d, want 800", cfg.VulnScanner.EnrichTimeoutMs)
	}
	if cfg.VulnScanner.MaxConcurrent != 8 {
		t.Errorf("MaxConcurrent = %d, want 8", cfg.VulnScanner.MaxConcurrent)
	}
	if cfg.VulnScanner.MaxPerRequest != 10 {
		t.Errorf("MaxPerRequest = %d, want 10", cfg.VulnScanner.MaxPerRequest)
	}
	if cfg.VulnScanner.MetricsIntervalMs != 30000 {
		t.Errorf("MetricsIntervalMs = %d, want 30000", cfg.VulnScanner.MetricsIntervalMs)
	}
}
