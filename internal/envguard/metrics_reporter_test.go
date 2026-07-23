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
