package vulnscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

func TestVulnScanner_MetricsSnapshot(t *testing.T) {
	// One dependency, two vulnerabilities (already hydrated with severity).
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: []OSVVulnerability{
				{ID: "CVE-A", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}},
				{ID: "CVE-B", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "5.0"}}},
			}},
		},
	}
	server := newTestOSVServer(t, osvResp)
	defer server.Close()

	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), nil)
	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})
	if _, err := handler.Handle(context.Background(), params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	handler.waitBackground()

	m := handler.MetricsSnapshot()
	if m.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", m.ScansTotal)
	}
	if m.VulnsFoundTotal != 2 {
		t.Errorf("VulnsFoundTotal = %d, want 2", m.VulnsFoundTotal)
	}
}

func TestVulnScanner_MetricsEnrichmentCounters(t *testing.T) {
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: []OSVVulnerability{{ID: "CVE-A", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}}}},
		},
	}
	server := newTestOSVServer(t, osvResp)
	defer server.Close()

	mockLLM := &mockLLMBackend{response: &llm.LLMResponse{Text: "fix it"}}
	notifier := &mockNotifier{}
	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), mockLLM)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}
	handler.waitBackground()

	m := handler.MetricsSnapshot()
	if m.EnrichmentsOK != 1 {
		t.Errorf("EnrichmentsOK = %d, want 1", m.EnrichmentsOK)
	}
	if m.EnrichmentsFailed != 0 {
		t.Errorf("EnrichmentsFailed = %d, want 0", m.EnrichmentsFailed)
	}
}

func TestVulnScanner_StartMetricsReporter(t *testing.T) {
	var buf bytes.Buffer
	handler := NewVulnScannerHandler(NewOSVClient(), nil)
	handler.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handler.StartMetricsReporter(ctx, 20*time.Millisecond)
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
