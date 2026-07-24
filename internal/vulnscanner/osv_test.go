package vulnscanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQueryBatch_Success(t *testing.T) {
	// Mock OSV.dev server that returns vulnerabilities for lodash
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("expected /v1/querybatch, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		// Verify request body structure
		var reqBody osvQueryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if len(reqBody.Queries) != 2 {
			t.Fatalf("expected 2 queries, got %d", len(reqBody.Queries))
		}

		resp := osvQueryBatchResponse{
			Results: []osvQueryResult{
				{
					Vulns: []OSVVulnerability{
						{
							ID:      "GHSA-xxxx-yyyy-zzzz",
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
												{Introduced: "0"},
												{Fixed: "4.17.21"},
											},
										},
									},
								},
							},
						},
					},
				},
				{
					Vulns: nil, // express has no vulns
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	deps := []Dependency{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
		{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
	}

	results, err := client.QueryBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// lodash should have vulnerabilities
	vulns, ok := results["lodash"]
	if !ok {
		t.Fatal("expected lodash to have vulnerabilities")
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability for lodash, got %d", len(vulns))
	}
	if vulns[0].ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("expected ID GHSA-xxxx-yyyy-zzzz, got %s", vulns[0].ID)
	}
	if vulns[0].Summary != "Prototype pollution in lodash" {
		t.Errorf("unexpected summary: %s", vulns[0].Summary)
	}
	if len(vulns[0].Severity) != 1 {
		t.Fatalf("expected 1 severity entry, got %d", len(vulns[0].Severity))
	}
	if vulns[0].Severity[0].Type != "CVSS_V3" {
		t.Errorf("expected severity type CVSS_V3, got %s", vulns[0].Severity[0].Type)
	}

	// express should not have vulnerabilities
	if _, ok := results["express"]; ok {
		t.Error("expected express to have no vulnerabilities")
	}
}

func TestQueryBatch_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := osvQueryBatchResponse{
			Results: []osvQueryResult{
				{Vulns: nil},
				{Vulns: nil},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	deps := []Dependency{
		{Name: "react", Version: "18.2.0", Ecosystem: "npm"},
		{Name: "typescript", Version: "5.0.0", Ecosystem: "npm"},
	}

	results, err := client.QueryBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected no results, got %d", len(results))
	}
}

func TestQueryBatch_EmptyDependencies(t *testing.T) {
	client := NewOSVClient()
	results, err := client.QueryBatch(context.Background(), []Dependency{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty map, got %d entries", len(results))
	}
}

func TestQueryBatch_APIErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	deps := []Dependency{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	}

	_, err := client.QueryBatch(context.Background(), deps)
	if err == nil {
		t.Fatal("expected error for non-200 status code")
	}

	expected := "osv: API returned status 500"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestQueryBatch_Timeout(t *testing.T) {
	// Server that delays longer than the timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than the context timeout we'll set
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	deps := []Dependency{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"},
	}

	// Use a short-lived parent context to simulate timeout behavior
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.QueryBatch(ctx, deps)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestQueryBatch_MultipleDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody osvQueryBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request: %v", err)
		}

		// Verify all 5 dependencies are in the batch
		if len(reqBody.Queries) != 5 {
			t.Fatalf("expected 5 queries, got %d", len(reqBody.Queries))
		}

		// Include severity so these are already "hydrated" (no follow-up calls);
		// this test focuses on index-to-dependency mapping.
		sev := []OSVSeverity{{Type: "CVSS_V3", Score: "5.0"}}
		resp := osvQueryBatchResponse{
			Results: []osvQueryResult{
				{
					Vulns: []OSVVulnerability{
						{ID: "CVE-2021-0001", Summary: "Vuln in pkg-a", Severity: sev},
					},
				},
				{Vulns: nil}, // pkg-b: no vulns
				{
					Vulns: []OSVVulnerability{
						{ID: "CVE-2021-0002", Summary: "Vuln 1 in pkg-c", Severity: sev},
						{ID: "CVE-2021-0003", Summary: "Vuln 2 in pkg-c", Severity: sev},
					},
				},
				{Vulns: nil}, // pkg-d: no vulns
				{
					Vulns: []OSVVulnerability{
						{ID: "CVE-2021-0004", Summary: "Vuln in pkg-e", Severity: sev},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	deps := []Dependency{
		{Name: "pkg-a", Version: "1.0.0", Ecosystem: "npm"},
		{Name: "pkg-b", Version: "2.0.0", Ecosystem: "npm"},
		{Name: "pkg-c", Version: "3.0.0", Ecosystem: "npm"},
		{Name: "pkg-d", Version: "4.0.0", Ecosystem: "PyPI"},
		{Name: "pkg-e", Version: "5.0.0", Ecosystem: "PyPI"},
	}

	results, err := client.QueryBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// pkg-a: 1 vuln
	if vulns, ok := results["pkg-a"]; !ok || len(vulns) != 1 {
		t.Errorf("expected 1 vuln for pkg-a, got %d", len(vulns))
	}

	// pkg-b: no vulns
	if _, ok := results["pkg-b"]; ok {
		t.Error("expected no vulns for pkg-b")
	}

	// pkg-c: 2 vulns
	if vulns, ok := results["pkg-c"]; !ok || len(vulns) != 2 {
		t.Errorf("expected 2 vulns for pkg-c, got %d", len(vulns))
	}

	// pkg-d: no vulns
	if _, ok := results["pkg-d"]; ok {
		t.Error("expected no vulns for pkg-d")
	}

	// pkg-e: 1 vuln
	if vulns, ok := results["pkg-e"]; !ok || len(vulns) != 1 {
		t.Errorf("expected 1 vuln for pkg-e, got %d", len(vulns))
	}
}

func TestNewOSVClient_DefaultURL(t *testing.T) {
	client := NewOSVClient()
	if client.baseURL != "https://api.osv.dev" {
		t.Errorf("expected default URL https://api.osv.dev, got %s", client.baseURL)
	}
	if client.httpClient == nil {
		t.Error("expected non-nil http client")
	}
}

func TestNewOSVClientWithURL_CustomURL(t *testing.T) {
	client := NewOSVClientWithURL("http://localhost:8080")
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("expected custom URL http://localhost:8080, got %s", client.baseURL)
	}
}

func TestGetVuln_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		full := OSVVulnerability{
			ID:       id,
			Summary:  "full detail",
			Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.8"}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(full)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	v, err := client.GetVuln(context.Background(), "GHSA-abcd-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "GHSA-abcd-1234" {
		t.Errorf("ID = %q, want GHSA-abcd-1234", v.ID)
	}
	if len(v.Severity) != 1 || v.Severity[0].Score != "9.8" {
		t.Errorf("expected severity 9.8, got %+v", v.Severity)
	}
}

func TestQueryBatch_HydratesMinimalVulns(t *testing.T) {
	// querybatch returns MINIMAL vulns (id only), like the real OSV API.
	// The client must hydrate them via /v1/vulns/{id}.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/querybatch":
			json.NewEncoder(w).Encode(osvQueryBatchResponse{
				Results: []osvQueryResult{
					{Vulns: []OSVVulnerability{{ID: "CVE-2021-0001"}}}, // minimal
				},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			json.NewEncoder(w).Encode(OSVVulnerability{
				ID:       id,
				Summary:  "hydrated summary",
				Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.8"}},
				Affected: []OSVAffected{
					{
						Package: OSVPackage{Name: "lodash", Ecosystem: "npm"},
						Ranges:  []OSVRange{{Type: "SEMVER", Events: []OSVEvent{{Introduced: "0"}, {Fixed: "4.17.21"}}}},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	results, err := client.QueryBatch(context.Background(), []Dependency{{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vulns := results["lodash"]
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "CVE-2021-0001" {
		t.Errorf("ID = %q, want CVE-2021-0001", vulns[0].ID)
	}
	if len(vulns[0].Severity) == 0 {
		t.Error("expected hydrated severity, got none")
	}
	if len(vulns[0].Affected) == 0 {
		t.Error("expected hydrated affected ranges, got none")
	}
	if vulns[0].Summary != "hydrated summary" {
		t.Errorf("Summary = %q, want hydrated summary", vulns[0].Summary)
	}
}

func TestGetVuln_RetriesExhausted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	_, err := client.GetVuln(context.Background(), "CVE-0000-0000")
	if err == nil {
		t.Fatal("expected error when retries exhausted")
	}
}

func TestGetVuln_BadRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	_, err := client.GetVuln(context.Background(), "CVE-0000-0000")
	if err == nil {
		t.Fatal("expected error for 400 status")
	}
}

func TestGetVuln_BadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"not json without closing`))
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	_, err := client.GetVuln(context.Background(), "CVE-0000-0000")
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("expected error containing 'decode', got: %v", err)
	}
}

func TestQueryBatch_HydrateFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/querybatch":
			json.NewEncoder(w).Encode(osvQueryBatchResponse{
				Results: []osvQueryResult{
					{Vulns: []OSVVulnerability{{ID: "CVE-2021-0001"}}},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	results, err := client.QueryBatch(context.Background(), []Dependency{{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("QueryBatch should not return error on hydrate failure: %v", err)
	}
	vulns := results["lodash"]
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].ID != "CVE-2021-0001" {
		t.Errorf("ID = %q, want CVE-2021-0001", vulns[0].ID)
	}
	if len(vulns[0].Severity) != 0 {
		t.Error("expected minimal vuln (no severity) on failed hydrate")
	}
}

func TestQueryBatch_BadJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	_, err := client.QueryBatch(context.Background(), []Dependency{{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}})
	if err == nil {
		t.Fatal("expected error for bad JSON response")
	}
}

func TestQueryBatch_ContextCancelledDuringRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	_, err := client.QueryBatch(ctx, []Dependency{{Name: "test", Version: "1.0", Ecosystem: "npm"}})
	if err == nil {
		t.Fatal("expected error when context cancelled during retry")
	}
}
