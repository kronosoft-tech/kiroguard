package vulnscanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestQueryBatch_RetriesTransientErrors(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // 503 twice
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(osvQueryBatchResponse{
			Results: []osvQueryResult{
				{Vulns: []OSVVulnerability{{ID: "CVE-1", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "9.0"}}}}},
			},
		})
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	results, err := client.QueryBatch(context.Background(), []Dependency{{Name: "lodash", Version: "4.17.0", Ecosystem: "npm"}})
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 attempts (2 failures + success), got %d", got)
	}
	if len(results["lodash"]) != 1 {
		t.Errorf("expected 1 vuln after retry, got %d", len(results["lodash"]))
	}
}

func TestGetVuln_RetriesTransientErrors(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests) // 429 once
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OSVVulnerability{ID: "CVE-1", Severity: []OSVSeverity{{Type: "CVSS_V3", Score: "7.0"}}})
	}))
	defer server.Close()

	client := NewOSVClientWithURL(server.URL)
	v, err := client.GetVuln(context.Background(), "CVE-1")
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if v.ID != "CVE-1" {
		t.Errorf("ID = %q, want CVE-1", v.ID)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 attempts (1 x 429 + success), got %d", got)
	}
}
