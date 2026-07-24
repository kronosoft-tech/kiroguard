package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigWatcher_HotReload(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	initialYAML := `
transport:
  type: stdio
  port: 3000
`
	if err := os.WriteFile(configFile, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	initialCfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("Load initial error: %v", err)
	}

	watcher, err := NewConfigWatcher(configFile, initialCfg)
	if err != nil {
		t.Fatalf("NewConfigWatcher error: %v", err)
	}

	var reloaded atomic.Bool
	watcher.RegisterCallback(func(newCfg *Config) {
		if newCfg.Transport.Port == 8080 {
			reloaded.Store(true)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Update config on disk
	updatedYAML := `
transport:
  type: sse
  port: 8080
`
	if err := os.WriteFile(configFile, []byte(updatedYAML), 0644); err != nil {
		t.Fatalf("failed to write updated config: %v", err)
	}

	// Wait up to 2 seconds for hot-reload event
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reloaded.Load() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !reloaded.Load() {
		t.Errorf("expected config hot-reload callback to fire with updated port 8080")
	}
	if watcher.Current().Transport.Port != 8080 {
		t.Errorf("Current().Transport.Port = %d, want 8080", watcher.Current().Transport.Port)
	}
}
