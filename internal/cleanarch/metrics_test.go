package cleanarch

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestHandler_ReportMetricsOnce_EmitsStructuredEvent(t *testing.T) {
	var buf bytes.Buffer
	handler := NewCleanArchHandler(nil, nil)
	handler.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	// Bump some counters directly.
	handler.metrics.ScansTotal.Add(2)
	handler.metrics.ViolationsTotal.Add(7)
	handler.metrics.EnrichmentsOK.Add(5)
	handler.metrics.EnrichmentsFailed.Add(1)

	handler.reportMetrics()

	out := buf.String()
	if !strings.Contains(out, `"event":"metrics_report"`) {
		t.Fatalf("expected metrics_report event, got: %s", out)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("log line is not valid JSON: %v", err)
	}
	if rec["scans_total"].(float64) != 2 {
		t.Errorf("scans_total = %v, want 2", rec["scans_total"])
	}
	if rec["violations_total"].(float64) != 7 {
		t.Errorf("violations_total = %v, want 7", rec["violations_total"])
	}
	if rec["enrichments_ok"].(float64) != 5 {
		t.Errorf("enrichments_ok = %v, want 5", rec["enrichments_ok"])
	}
	if rec["enrichments_failed"].(float64) != 1 {
		t.Errorf("enrichments_failed = %v, want 1", rec["enrichments_failed"])
	}
}

func TestHandler_StartMetricsReporter_TicksAndStopsOnCancel(t *testing.T) {
	var buf bytes.Buffer
	handler := NewCleanArchHandler(nil, nil)
	handler.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		handler.StartMetricsReporter(ctx, 20*time.Millisecond)
		close(done)
	}()

	// Let it tick a few times.
	time.Sleep(90 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("StartMetricsReporter did not return after context cancel")
	}

	if n := strings.Count(buf.String(), `"event":"metrics_report"`); n < 2 {
		t.Errorf("expected multiple metrics_report emissions, got %d", n)
	}
}
