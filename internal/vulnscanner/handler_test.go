package vulnscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// mockLLMBackend is a simple LLM backend for testing.
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
	// Set up a mock OSV server that returns vulnerabilities
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
									{
										Type: "SEMVER",
										Events: []OSVEvent{
											{Introduced: "1.0.0"},
											{Fixed: "4.17.21"},
										},
									},
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

	client := NewOSVClientWithURL(server.URL)
	handler := NewVulnScannerHandler(client, nil)

	input := VulnScannerInput{
		Manifest:  `{"dependencies": {"lodash": "^4.17.0"}}`,
		Ecosystem: "npm",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output, ok := result.(*VulnScannerOutput)
	if !ok {
		t.Fatalf("expected *VulnScannerOutput, got %T", result)
	}

	if output.TotalDeps != 1 {
		t.Errorf("expected TotalDeps=1, got %d", output.TotalDeps)
	}
	if output.VulnCount != 1 {
		t.Errorf("expected VulnCount=1, got %d", output.VulnCount)
	}
	if output.ScanError != "" {
		t.Errorf("expected no ScanError, got: %s", output.ScanError)
	}
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	f := output.Findings[0]
	if f.CVEID != "CVE-2021-12345" {
		t.Errorf("expected CVEID=CVE-2021-12345, got %s", f.CVEID)
	}
	if f.PackageName != "lodash" {
		t.Errorf("expected PackageName=lodash, got %s", f.PackageName)
	}
	if f.Severity == 0.0 {
		t.Error("expected non-zero severity score")
	}
	if f.AffectedRange != ">=1.0.0, <4.17.21" {
		t.Errorf("expected AffectedRange='>=1.0.0, <4.17.21', got '%s'", f.AffectedRange)
	}
	if f.FixedVersion != "4.17.21" {
		t.Errorf("expected FixedVersion=4.17.21, got %s", f.FixedVersion)
	}
}

func TestHandle_ValidScanNoVulnerabilities(t *testing.T) {
	// OSV server returns no vulnerabilities
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{Vulns: nil},
		},
	}

	server := newTestOSVServer(t, osvResp)
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	handler := NewVulnScannerHandler(client, nil)

	input := VulnScannerInput{
		Manifest:  `{"dependencies": {"express": "4.18.2"}}`,
		Ecosystem: "npm",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output := result.(*VulnScannerOutput)
	if output.TotalDeps != 1 {
		t.Errorf("expected TotalDeps=1, got %d", output.TotalDeps)
	}
	if output.VulnCount != 0 {
		t.Errorf("expected VulnCount=0, got %d", output.VulnCount)
	}
	if len(output.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(output.Findings))
	}
	if output.ScanError != "" {
		t.Errorf("expected no ScanError, got: %s", output.ScanError)
	}
}

func TestHandle_InvalidParams(t *testing.T) {
	client := NewOSVClient()
	handler := NewVulnScannerHandler(client, nil)

	tests := []struct {
		name   string
		params json.RawMessage
	}{
		{
			name:   "invalid JSON",
			params: json.RawMessage(`{not valid json`),
		},
		{
			name:   "empty manifest",
			params: json.RawMessage(`{"manifest": "", "ecosystem": "npm"}`),
		},
		{
			name:   "empty ecosystem",
			params: json.RawMessage(`{"manifest": "{}", "ecosystem": ""}`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.Handle(context.Background(), tc.params)
			if err == nil {
				t.Error("expected error for invalid params, got nil")
			}
		})
	}
}

func TestHandle_OSVErrorCapturedInScanError(t *testing.T) {
	// Set up a server that returns a 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	handler := NewVulnScannerHandler(client, nil)

	input := VulnScannerInput{
		Manifest:  `{"dependencies": {"lodash": "4.17.0"}}`,
		Ecosystem: "npm",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("Handle should not return error on OSV failure, got: %v", err)
	}

	output := result.(*VulnScannerOutput)
	if output.ScanError == "" {
		t.Error("expected ScanError to be set when OSV fails")
	}
	if output.TotalDeps != 1 {
		t.Errorf("expected TotalDeps=1 even on OSV error, got %d", output.TotalDeps)
	}
	if output.VulnCount != 0 {
		t.Errorf("expected VulnCount=0 on OSV error, got %d", output.VulnCount)
	}
}

func TestHandle_LLMExplanationsIncluded(t *testing.T) {
	// Set up OSV server with a vulnerability
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []OSVVulnerability{
					{
						ID:      "GHSA-test-1234",
						Summary: "Test vulnerability",
						Affected: []OSVAffected{
							{
								Package: OSVPackage{Name: "axios", Ecosystem: "npm"},
								Ranges: []OSVRange{
									{
										Type: "SEMVER",
										Events: []OSVEvent{
											{Introduced: "0.1.0"},
											{Fixed: "0.21.1"},
										},
									},
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

	// Set up mock LLM that returns explanations
	mockLLM := &mockLLMBackend{
		response: &llm.LLMResponse{
			Text:     "This vulnerability allows remote code execution via crafted input.",
			Metadata: map[string]string{},
		},
	}

	client := NewOSVClientWithURL(server.URL)
	handler := NewVulnScannerHandler(client, mockLLM)

	input := VulnScannerInput{
		Manifest:  `{"dependencies": {"axios": "0.19.0"}}`,
		Ecosystem: "npm",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output := result.(*VulnScannerOutput)
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	f := output.Findings[0]
	if f.Explanation == "" {
		t.Error("expected explanation to be set when LLM is available")
	}
	if f.Explanation != "This vulnerability allows remote code execution via crafted input." {
		t.Errorf("unexpected explanation: %s", f.Explanation)
	}
}

func TestHandle_LLMErrorDoesNotFailScan(t *testing.T) {
	// Set up OSV server with a vulnerability
	osvResp := osvQueryBatchResponse{
		Results: []osvQueryResult{
			{
				Vulns: []OSVVulnerability{
					{
						ID: "CVE-2022-9999",
						Affected: []OSVAffected{
							{
								Package: OSVPackage{Name: "requests", Ecosystem: "pypi"},
								Ranges: []OSVRange{
									{
										Type: "ECOSYSTEM",
										Events: []OSVEvent{
											{Introduced: "2.0.0"},
											{Fixed: "2.28.0"},
										},
									},
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

	// Set up mock LLM that returns an error
	mockLLM := &mockLLMBackend{
		err: fmt.Errorf("LLM service unavailable"),
	}

	client := NewOSVClientWithURL(server.URL)
	handler := NewVulnScannerHandler(client, mockLLM)

	input := VulnScannerInput{
		Manifest:  "requests==2.25.0\n",
		Ecosystem: "pip",
	}
	params, _ := json.Marshal(input)

	result, err := handler.Handle(context.Background(), params)
	if err != nil {
		t.Fatalf("expected no error even with LLM failure, got: %v", err)
	}

	output := result.(*VulnScannerOutput)
	if len(output.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(output.Findings))
	}

	// Explanation should be empty when LLM fails, but scan still succeeds
	f := output.Findings[0]
	if f.Explanation != "" {
		t.Errorf("expected empty explanation on LLM error, got: %s", f.Explanation)
	}
	if f.CVEID != "CVE-2022-9999" {
		t.Errorf("expected CVEID=CVE-2022-9999, got %s", f.CVEID)
	}
}

func TestRegisterVulnScanner(t *testing.T) {
	d := rpc.NewDispatcher()
	client := NewOSVClient()
	handler := NewVulnScannerHandler(client, nil)

	RegisterVulnScanner(d, handler)

	// Verify the handler is registered by dispatching a request
	reqID := json.RawMessage(`1`)
	req := &rpc.Request{
		JSONRPC: "2.0",
		ID:      &reqID,
		Method:  "vulnscanner/scan",
		Params:  json.RawMessage(`{"manifest": "", "ecosystem": "npm"}`),
	}

	resp := d.Dispatch(context.Background(), req)
	// Should get an error response (invalid params) rather than method not found
	if resp.Error == nil {
		t.Fatal("expected error response for empty manifest")
	}
	if resp.Error.Code == -32601 {
		t.Error("handler was not registered - got method not found error")
	}
}

func TestMapOSVToFinding_MultipleRanges(t *testing.T) {
	vuln := OSVVulnerability{
		ID: "CVE-2023-0001",
		Severity: []OSVSeverity{
			{Type: "CVSS_V3", Score: "7.5"},
		},
		Affected: []OSVAffected{
			{
				Package: OSVPackage{Name: "foo", Ecosystem: "npm"},
				Ranges: []OSVRange{
					{
						Type: "SEMVER",
						Events: []OSVEvent{
							{Introduced: "2.0.0"},
							{Fixed: "2.5.1"},
						},
					},
				},
			},
		},
	}

	finding := mapOSVToFinding("foo", vuln)

	if finding.CVEID != "CVE-2023-0001" {
		t.Errorf("expected CVEID=CVE-2023-0001, got %s", finding.CVEID)
	}
	if finding.Severity != 7.5 {
		t.Errorf("expected Severity=7.5, got %f", finding.Severity)
	}
	if finding.AffectedRange != ">=2.0.0, <2.5.1" {
		t.Errorf("expected AffectedRange='>=2.0.0, <2.5.1', got '%s'", finding.AffectedRange)
	}
	if finding.FixedVersion != "2.5.1" {
		t.Errorf("expected FixedVersion=2.5.1, got %s", finding.FixedVersion)
	}
}

func TestParseSeverityScore(t *testing.T) {
	tests := []struct {
		name       string
		severities []OSVSeverity
		wantMin    float64
		wantMax    float64
	}{
		{
			name:       "empty severities",
			severities: nil,
			wantMin:    0.0,
			wantMax:    0.0,
		},
		{
			name:       "direct numeric score",
			severities: []OSVSeverity{{Type: "CVSS_V3", Score: "9.8"}},
			wantMin:    9.8,
			wantMax:    9.8,
		},
		{
			name:       "CVSS vector with high impact",
			severities: []OSVSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			wantMin:    7.0,
			wantMax:    10.0,
		},
		{
			name:       "empty score string",
			severities: []OSVSeverity{{Type: "CVSS_V3", Score: ""}},
			wantMin:    0.0,
			wantMax:    0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := parseSeverityScore(tc.severities)
			if score < tc.wantMin || score > tc.wantMax {
				t.Errorf("expected score in [%f, %f], got %f", tc.wantMin, tc.wantMax, score)
			}
		})
	}
}
