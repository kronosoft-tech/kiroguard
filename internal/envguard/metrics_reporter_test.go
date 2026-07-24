package envguard

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestEnvGuard_StartMetricsReporter_ZeroInterval_FallsBack(t *testing.T) {
	var buf bytes.Buffer
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	h := NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
	h.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// interval=0 should fall back to defaultMetricsInterval
		h.StartMetricsReporter(ctx, 0)
		close(done)
	}()

	// Wait a tick, then cancel
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartMetricsReporter did not return after cancel")
	}

	// Should have emitted at least one metrics_report
	if !strings.Contains(buf.String(), `"event":"metrics_report"`) {
		t.Error("expected metrics_report event with zero interval fallback")
	}
}

func TestEnvGuard_StartMetricsReporter_TicksAndStops(t *testing.T) {
	var buf bytes.Buffer
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	h := NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
	h.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.StartMetricsReporter(ctx, 20*time.Millisecond)
		close(done)
	}()

	time.Sleep(90 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartMetricsReporter did not return after cancel")
	}

	if n := strings.Count(buf.String(), `"event":"metrics_report"`); n < 2 {
		t.Errorf("expected multiple metrics_report emissions, got %d", n)
	}
}
