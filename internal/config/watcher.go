package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloadCallback is invoked whenever a watched configuration file is modified on disk.
type ReloadCallback func(newCfg *Config)

// ConfigWatcher monitors configuration files on disk using OS-native events (fsnotify).
// When a file changes, it reloads and validates the configuration, updating the in-memory
// state without interrupting active RPC sessions (Hot-Reloading).
type ConfigWatcher struct {
	configPath string
	watcher    *fsnotify.Watcher
	callbacks  []ReloadCallback
	mu         sync.RWMutex
	current    *Config

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewConfigWatcher initializes an fsnotify watcher for the target configPath.
func NewConfigWatcher(configPath string, initial *Config) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	cw := &ConfigWatcher{
		configPath: configPath,
		watcher:    watcher,
		current:    initial,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	if configPath != "" {
		absPath, absErr := filepath.Abs(configPath)
		if absErr == nil {
			if _, statErr := os.Stat(absPath); statErr == nil {
				if err := watcher.Add(absPath); err != nil {
					slog.Warn("failed to watch config file", "path", absPath, "error", err)
				} else {
					slog.Info("config hot-reloading active", "watching", absPath)
				}
			}
		}
	}

	return cw, nil
}

// RegisterCallback registers a subscriber callback to be called on hot-reload.
func (cw *ConfigWatcher) RegisterCallback(cb ReloadCallback) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.callbacks = append(cw.callbacks, cb)
}

// Current returns the current thread-safe snapshot of the Config.
func (cw *ConfigWatcher) Current() *Config {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.current
}

// Start begins listening for file modification events in a background goroutine.
func (cw *ConfigWatcher) Start(ctx context.Context) {
	go cw.loop(ctx)
}

// Stop terminates the watcher goroutine cleanly.
func (cw *ConfigWatcher) Stop() {
	close(cw.stopCh)
	<-cw.doneCh
	_ = cw.watcher.Close()
}

func (cw *ConfigWatcher) loop(ctx context.Context) {
	defer close(cw.doneCh)
	var debounceTimer *time.Timer
	const debounceDuration = 100 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return
		case <-cw.stopCh:
			return
		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("config watcher error", "error", err)
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDuration, func() {
					cw.reload()
				})
			}
		}
	}
}

func (cw *ConfigWatcher) reload() {
	slog.Info("detected config file change, hot-reloading...", "file", cw.configPath)

	newCfg, err := Load(cw.configPath)
	if err != nil {
		slog.Error("failed to hot-reload config: validation error", "error", err)
		return
	}

	cw.mu.Lock()
	cw.current = newCfg
	callbacks := make([]ReloadCallback, len(cw.callbacks))
	copy(callbacks, cw.callbacks)
	cw.mu.Unlock()

	slog.Info("config hot-reloaded successfully", "file", cw.configPath)

	for _, cb := range callbacks {
		cb(newCfg)
	}
}
