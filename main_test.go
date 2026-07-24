package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/time/rate"

	"github.com/luiferdev/kiroguard/internal/cleanarch"
	"github.com/luiferdev/kiroguard/internal/envguard"
	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
	"github.com/luiferdev/kiroguard/internal/vulnscanner"
)

// buildIntegratedDispatcher wires Clean-Arch, Env-Guard and Vuln-Scanner onto a
// single dispatcher, mirroring the composition performed in main(). It uses the
// heuristic LLM backend so the test needs no AWS credentials, and points the OSV
// client at a local mock server (osvURL) so it needs no network.
func buildIntegratedDispatcher(osvURL string) *rpc.Dispatcher {
	d := rpc.NewDispatcher()

	heuristic := llm.NewHeuristicProvider()

	arch := cleanarch.NewCleanArchHandler(nil, heuristic)
	cleanarch.RegisterCleanArch(d, arch)

	scanner := envguard.NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(10), 5)
	env := envguard.NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
	envguard.RegisterEnvGuard(d, env)

	vuln := vulnscanner.NewVulnScannerHandler(vulnscanner.NewOSVClientWithURL(osvURL), heuristic)
	vulnscanner.RegisterVulnScanner(d, vuln)

	return d
}

func dispatch(t *testing.T, d *rpc.Dispatcher, method string, params any) *rpc.Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	id := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &id, Method: method, Params: raw}
	return d.Dispatch(context.Background(), req)
}

// newMockOSV returns a local OSV.dev stand-in that reports one vulnerability
// (already carrying severity, so no /v1/vulns hydration is needed).
func newMockOSV(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{
				{"vulns": []map[string]any{
					{"id": "CVE-2021-23337", "summary": "Command injection in lodash",
						"severity": []map[string]any{{"type": "CVSS_V3", "score": "7.2"}}},
				}},
			},
		})
	}))
}

// TestIntegration_AllThreeModulesCoexist verifies the three production modules
// register on one dispatcher, each responds correctly, and routing is isolated.
func TestIntegration_AllThreeModulesCoexist(t *testing.T) {
	osv := newMockOSV(t)
	defer osv.Close()

	d := buildIntegratedDispatcher(osv.URL)

	// --- Clean-Arch: domain importing infrastructure is a violation. ---
	tmp := t.TempDir()
	domainDir := filepath.Join(tmp, "domain")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := "package domain\n\nimport \"github.com/myapp/infrastructure/database\"\n\nvar _ = database.Connect\n"
	if err := os.WriteFile(filepath.Join(domainDir, "service.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	archResp := dispatch(t, d, "cleanarch/analyze", cleanarch.CleanArchInput{DirectoryPath: tmp})
	if archResp.Error != nil {
		t.Fatalf("cleanarch/analyze error: %+v", archResp.Error)
	}
	var archOut cleanarch.CleanArchOutput
	if err := json.Unmarshal(archResp.Result, &archOut); err != nil {
		t.Fatalf("decode cleanarch: %v", err)
	}
	if len(archOut.Violations) != 1 {
		t.Errorf("cleanarch: expected 1 violation, got %d", len(archOut.Violations))
	}

	// --- Env-Guard: a diff adding an AWS access key must be blocked. ---
	diff := "+\tapiKey := \"AKIAIOSFODNN7EXAMPLE\"\n"
	envResp := dispatch(t, d, "envguard/scan", envguard.EnvGuardInput{Diff: diff, FilePath: "config.go"})
	if envResp.Error != nil {
		t.Fatalf("envguard/scan error: %+v", envResp.Error)
	}
	var envOut envguard.EnvGuardOutput
	if err := json.Unmarshal(envResp.Result, &envOut); err != nil {
		t.Fatalf("decode envguard: %v", err)
	}
	if !envOut.Blocked {
		t.Errorf("envguard: expected the secret to be blocked, got %+v", envOut)
	}

	// --- Vuln-Scanner: a manifest with a vulnerable dep must report a finding. ---
	vulnResp := dispatch(t, d, "vulnscanner/scan", vulnscanner.VulnScannerInput{
		Manifest:  `{"dependencies":{"lodash":"4.17.0"}}`,
		Ecosystem: "npm",
	})
	if vulnResp.Error != nil {
		t.Fatalf("vulnscanner/scan error: %+v", vulnResp.Error)
	}
	var vulnOut vulnscanner.VulnScannerOutput
	if err := json.Unmarshal(vulnResp.Result, &vulnOut); err != nil {
		t.Fatalf("decode vulnscanner: %v", err)
	}
	if vulnOut.ScanError != "" {
		t.Errorf("vulnscanner: unexpected scan_error: %s", vulnOut.ScanError)
	}
	if vulnOut.VulnCount != 1 || len(vulnOut.Findings) != 1 {
		t.Fatalf("vulnscanner: expected 1 finding, got %d", vulnOut.VulnCount)
	}
	if vulnOut.Findings[0].CVEID != "CVE-2021-23337" {
		t.Errorf("vulnscanner: CVEID = %q, want CVE-2021-23337", vulnOut.Findings[0].CVEID)
	}

	// --- Routing isolation: an unknown method resolves to none of them. ---
	unknown := dispatch(t, d, "does/not-exist", map[string]string{})
	if unknown.Error == nil || unknown.Error.Code != rpc.CodeMethodNotFound {
		t.Errorf("expected MethodNotFound for unknown method, got %+v", unknown.Error)
	}
}
