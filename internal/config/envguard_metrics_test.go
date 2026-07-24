package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault_EnvGuardMetricsInterval(t *testing.T) {
	cfg := Default()
	if cfg.EnvGuard.MetricsIntervalMs != 60000 {
		t.Errorf("EnvGuard.MetricsIntervalMs = %d, want 60000", cfg.EnvGuard.MetricsIntervalMs)
	}
}

func TestLoad_EnvGuardMetricsIntervalOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "envguard:\n  metrics_interval_ms: 15000\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.EnvGuard.MetricsIntervalMs != 15000 {
		t.Errorf("MetricsIntervalMs = %d, want 15000", cfg.EnvGuard.MetricsIntervalMs)
	}
}
