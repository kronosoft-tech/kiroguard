package vulnscanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// mockLLMBackend is a hand-written LLM backend for testing (no mocking libs).
type mockLLMBackend struct {
	response *llm.LLMResponse
	err      error
}

func (m *mockLLMBackend) Complete(_ context.Context, _ llm.Prompt) (*llm.LLMResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

// mockNotifier captures notifications emitted by the handler. Thread-safe.
type mockNotifier struct {
	mu   sync.Mutex
	msgs []*rpc.Response
}

func (m *mockNotifier) Send(_ context.Context, msg *rpc.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, msg)
	return nil
}

func (m *mockNotifier) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.msgs)
}

func (m *mockNotifier) enrichments(t *testing.T) []FindingEnrichment {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]FindingEnrichment, 0, len(m.msgs))
	for _, msg := range m.msgs {
		if msg.Method != "notifications/message" {
			t.Errorf("notification method = %q, want notifications/message", msg.Method)
		}
		var p struct {
			Data FindingEnrichment `json:"data"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil {
			t.Fatalf("failed to parse notification params: %v", err)
		}
		out = append(out, p.Data)
	}
	return out
}

// newTestOSVServer creates a test HTTP server that mimics the OSV.dev API.
func newTestOSVServer(t *testing.T, response interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
}

func TestHandle_ValidScanWithVulnerabilities(t *testing.T) {
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []OSVVulnerability{
					{
						ID:      "CVE-2021-12345",
						Summary: "Prototype pollution in lodash",
						Severity: []OSVSeverity{
							{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
						},
						Affected: []OSVAffected{
							{
								Package: OSVPackage{Name: "lodash", Ecosystem: "npm"},
								Ranges: []OSVRange{
									{Type: "SEMVER", Events: []OSVEvent{{Introduced: "1.0.0"}, {Fixed: "4.17.21"}}},
								},
							},
						},
					},
				},
			},
		},
	}
	server := newTestOSVServer(t, osvResp)
	defer server.Close()

	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), nil)
	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "^4.17.0"}}`, Ecosystem: "npm"})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := result.(*VulnScannerOutput)
	if output.TotalDeps != 1 || output.VulnCount != 1 || len(output.Findings) != 1 {
		t.Fatalf("unexpected counts: totalDeps=%d vulnCount=%d findings=%d", output.TotalDeps, output.VulnCount, len(output.Findings))
	}
	f := output.Findings[0]
	if f.CVEID != "CVE-2021-12345" || f.PackageName != "lodash" || f.Severity == 0 {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.AffectedRange != ">=1.0.0, <4.17.21" || f.FixedVersion != "4.17.21" {
		t.Errorf("unexpected range/fixed: %q / %q", f.AffectedRange, f.FixedVersion)
	}
}

func TestHandle_ValidScanNoVulnerabilities(t *testing.T) {
	server := newTestOSVServer(t, osvQueryBatchResponse{Results: []osvQueryResult{{Vulns: nil}}})
	defer server.Close()

	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), nil)
	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"express": "4.18.2"}}`, Ecosystem: "npm"})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := result.(*VulnScannerOutput)
	if output.TotalDeps != 1 || output.VulnCount != 0 || len(output.Findings) != 0 || output.ScanError != "" {
		t.Errorf("unexpected output: %+v", output)
	}
}

func TestHandle_InvalidParams(t *testing.T) {
	handler := NewVulnScannerHandler(NewOSVClient(), nil)

	cases := []struct {
		name   string
		params json.RawMessage
	}{
		{"invalid JSON", json.RawMessage(`{not valid json`)},
		{"empty manifest", json.RawMessage(`{"manifest": "", "ecosystem": "npm"}`)},
		{"empty ecosystem", json.RawMessage(`{"manifest": "{}", "ecosystem": ""}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.Handle(context.Background(), tc.params)
			if err == nil {
				t.Fatal("expected error")
			}
			var ve *rpc.ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("expected error to wrap *rpc.ValidationError (maps to -32602), got %T: %v", err, err)
			}
		})
	}
}

func TestHandle_ManifestTooLarge(t *testing.T) {
	handler := NewVulnScannerHandler(NewOSVClient(), nil)
	huge := strings.Repeat("a", 5*1024*1024+1) // > 5 MB
	params, _ := json.Marshal(VulnScannerInput{Manifest: huge, Ecosystem: "npm"})

	_, err := handler.Handle(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for oversized manifest")
	}
	var ve *rpc.ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *rpc.ValidationError (-32602), got %T: %v", err, err)
	}
}

func TestHandle_OSVErrorCapturedInScanError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), nil)
	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle must not error on OSV failure, got: %v", err)
	}
	output := result.(*VulnScannerOutput)
	if output.ScanError == "" {
		t.Error("expected ScanError to be set")
	}
	if output.TotalDeps != 1 {
		t.Errorf("expected TotalDeps=1 even on OSV error, got %d", output.TotalDeps)
	}
}

func TestHandle_NoNotifierNoEnrichment(t *testing.T) {
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: []OSVVulnerability{{ID: "CVE-2021-1", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}}}},
		},
	}
	server := newTestOSVServer(t, osvResp)
	defer server.Close()

	mockLLM := &mockLLMBackend{response: &llm.LLMResponse{Text: "should not be used"}}
	// LLM available but NO notifier → enrichment must be skipped entirely.
	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), mockLLM)
	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := result.(*VulnScannerOutput)
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}
	if output.Findings[0].Explanation != "" {
		t.Errorf("expected no inline explanation, got %q", output.Findings[0].Explanation)
	}
	if output.RequestID != "" {
		t.Errorf("expected empty request_id without a notifier, got %q", output.RequestID)
	}
	handler.waitBackground()
}

func TestHandle_AsyncEnrichmentNotifications(t *testing.T) {
	// One dependency with 7 vulnerabilities of varying severity.
	vulns := make([]OSVVulnerability, 7)
	scores := []string{"9.9", "9.5", "8.0", "7.0", "6.0", "5.0", "3.0"}
	for i := range vulns {
		vulns[i] = OSVVulnerability{
			ID:       fmt.Sprintf("CVE-2021-%04d", i),
			Severity: []OSVSeverity{{Type: "CVSS_V3", Score: scores[i]}},
			Affected: []OSVAffected{{Package: OSVPackage{Name: "lodash", Ecosystem: "npm"}}},
		}
	}
	server := newTestOSVServer(t, osvQueryBatchResponse{Results: []osvQueryResult{{Vulns: vulns}}})
	defer server.Close()

	mockLLM := &mockLLMBackend{response: &llm.LLMResponse{Text: "Actionable fix: upgrade the package."}}
	notifier := &mockNotifier{}
	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), mockLLM)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	result, err := handler.Handle(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := result.(*VulnScannerOutput)

	// Immediate response: request_id present, explanations empty.
	if output.RequestID == "" {
		t.Fatal("expected a request_id in the immediate response")
	}
	if output.VulnCount != 7 {
		t.Errorf("expected VulnCount=7, got %d", output.VulnCount)
	}
	for i, f := range output.Findings {
		if f.Explanation != "" {
			t.Errorf("finding[%d] should have empty explanation in immediate response, got %q", i, f.Explanation)
		}
	}

	handler.waitBackground()

	// Exactly 5 enrichment notifications (top-5 by severity).
	if notifier.count() != 5 {
		t.Fatalf("expected exactly 5 enrichment notifications, got %d", notifier.count())
	}
	for _, e := range notifier.enrichments(t) {
		if e.RequestID != output.RequestID {
			t.Errorf("notification request_id = %q, want %q", e.RequestID, output.RequestID)
		}
		if e.AIExplanation == "" {
			t.Error("expected non-empty ai_explanation in notification")
		}
		if e.FindingIndex < 0 || e.FindingIndex >= 5 {
			t.Errorf("finding_index = %d, want within top-5 [0,5)", e.FindingIndex)
		}
	}
}

func TestHandle_AsyncNotificationErrorDropped(t *testing.T) {
	server := newTestOSVServer(t, osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: []OSVVulnerability{{ID: "CVE-2021-1", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}}}},
		},
	})
	defer server.Close()

	mockLLM := &mockLLMBackend{err: errors.New("bedrock unavailable")}
	notifier := &mockNotifier{}
	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), mockLLM)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})
	ctx := rpc.WithClientID(context.Background(), "sess-1")
	if _, err := handler.Handle(ctx, params); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler.waitBackground()

	if notifier.count() != 0 {
		t.Errorf("expected no notifications when LLM fails, got %d", notifier.count())
	}
}

func TestHandle_NoSessionNoEnrichment(t *testing.T) {
	server := newTestOSVServer(t, osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: []OSVVulnerability{{ID: "CVE-2021-1", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}}}},
		},
	})
	defer server.Close()

	mockLLM := &mockLLMBackend{response: &llm.LLMResponse{Text: "should not fire"}}
	notifier := &mockNotifier{}
	handler := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), mockLLM)
	handler.SetNotifier(notifier)

	params, _ := json.Marshal(VulnScannerInput{Manifest: `{"dependencies": {"lodash": "4.17.0"}}`, Ecosystem: "npm"})
	// No client/session id in the context → enrichment must be skipped to avoid
	// broadcasting one caller's enrichment to unrelated clients.
	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	output := result.(*VulnScannerOutput)
	if output.RequestID != "" {
		t.Errorf("expected empty request_id without a session, got %q", output.RequestID)
	}

	handler.waitBackground()
	if notifier.count() != 0 {
		t.Errorf("expected no notifications without a session, got %d", notifier.count())
	}
}

func TestRegisterVulnScanner(t *testing.T) {
	d := rpc.NewDispatcher()
	RegisterVulnScanner(d, NewVulnScannerHandler(NewOSVClient(), nil))

	reqID := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &reqID, Method: "vulnscanner/scan", Params: json.RawMessage(`{"manifest": "", "ecosystem": "npm"}`)}
	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response for empty manifest")
	}
	if resp.Error.Code == rpc.CodeMethodNotFound {
		t.Error("handler was not registered (method not found)")
	}
	if resp.Error.Code != rpc.CodeInvalidParams {
		t.Errorf("expected -32602 for empty manifest, got %d", resp.Error.Code)
	}
}

func TestMapOSVToFinding_MultipleRanges(t *testing.T) {
	vuln := OSVVulnerability{
		ID:       "CVE-2023-0001",
		Summary:  "Prototype pollution",
		Details:  "An attacker can pollute Object.prototype",
		Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "7.5"}},
		Affected: []OSVAffected{
			{
				Package: OSVPackage{Name: "foo", Ecosystem: "npm"},
				Ranges:  []OSVRange{{Type: "SEMVER", Events: []OSVEvent{{Introduced: "2.0.0"}, {Fixed: "2.5.1"}}}},
			},
		},
	}
	finding := mapOSVToFinding("foo", vuln)
	if finding.CVEID != "CVE-2023-0001" || finding.Severity != 7.5 {
		t.Errorf("unexpected finding: %+v", finding)
	}
	if finding.AffectedRange != ">=2.0.0, <2.5.1" || finding.FixedVersion != "2.5.1" {
		t.Errorf("unexpected range/fixed: %q / %q", finding.AffectedRange, finding.FixedVersion)
	}
	if finding.Summary != "Prototype pollution" {
		t.Errorf("Summary = %q, want %q", finding.Summary, "Prototype pollution")
	}
	if finding.Details != "An attacker can pollute Object.prototype" {
		t.Errorf("Details = %q", finding.Details)
	}
}

func TestBuildPrompt_UsesSummaryDetailsAndTruncates(t *testing.T) {
	h := NewVulnScannerHandler(NewOSVClient(), nil)
	f := VulnFinding{
		CVEID:         "CVE-2021-12345",
		PackageName:   "lodash",
		Severity:      9.8,
		AffectedRange: ">=0, <4.17.21",
		Summary:       "Prototype pollution in lodash",
		Details:       strings.Repeat("x", 1000), // very long details must be truncated
	}
	p := h.buildPrompt(f)

	// Must include the human-readable summary (directive #4).
	if !strings.Contains(p.User, "Prototype pollution in lodash") {
		t.Errorf("prompt should include the summary; got: %q", p.User)
	}
	// Token efficiency: system+user must stay small (<= 500 chars per design §4.1).
	if total := len(p.System) + len(p.User); total > 500 {
		t.Errorf("prompt too long: %d chars (want <= 500)", total)
	}
	// The 1000-char details must be truncated, not dumped verbatim.
	if strings.Contains(p.User, strings.Repeat("x", 500)) {
		t.Error("details were not truncated")
	}
}

func TestParseSeverityScore(t *testing.T) {
	cases := []struct {
		name       string
		severities []OSVSeverity
		min, max   float64
	}{
		{"empty", nil, 0, 0},
		{"direct numeric", []OSVSeverity{{Type: "CVSS_V3", Score: "9.8"}}, 9.8, 9.8},
		{"cvss vector high", []OSVSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, 7.0, 10.0},
		{"empty string", []OSVSeverity{{Type: "CVSS_V3", Score: ""}}, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score := parseSeverityScore(tc.severities)
			if score < tc.min || score > tc.max {
				t.Errorf("score=%f, want in [%f,%f]", score, tc.min, tc.max)
			}
		})
	}
}
