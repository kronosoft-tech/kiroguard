package vulnscanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"pgregory.net/rapid"
)

// Feature: vulnscanner, Property 9: Vulnerability response structure
// Every OSV vulnerability with a non-empty ID maps to a VulnFinding whose CVEID
// is non-empty and whose severity is within [0, 10]; a fixed event is preserved.
func TestProperty_VulnFindingStructure(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := "CVE-" + rapid.StringMatching(`[0-9]{4}-[0-9]{3,5}`).Draw(t, "id")
		sevStr := rapid.SampledFrom([]string{
			"", "9.8", "7.5", "3.1",
			"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}).Draw(t, "sev")
		introduced := rapid.SampledFrom([]string{"", "1.0.0", "2.3.4"}).Draw(t, "introduced")
		fixed := rapid.SampledFrom([]string{"", "4.17.21", "2.0.0"}).Draw(t, "fixed")

		vuln := OSVVulnerability{
			ID:       id,
			Severity: []OSVSeverity{{Type: "CVSS_V3", Score: sevStr}},
			Affected: []OSVAffected{
				{
					Package: OSVPackage{Name: "pkg", Ecosystem: "npm"},
					Ranges:  []OSVRange{{Type: "SEMVER", Events: []OSVEvent{{Introduced: introduced}, {Fixed: fixed}}}},
				},
			},
		}

		f := mapOSVToFinding("pkg", vuln)

		if f.CVEID == "" || f.CVEID != id {
			t.Errorf("CVEID = %q, want non-empty %q", f.CVEID, id)
		}
		if f.Severity < 0 || f.Severity > 10 {
			t.Errorf("severity %f out of range [0,10]", f.Severity)
		}
		if fixed != "" && f.FixedVersion != fixed {
			t.Errorf("FixedVersion = %q, want %q", f.FixedVersion, fixed)
		}
		if f.PackageName != "pkg" {
			t.Errorf("PackageName = %q, want pkg", f.PackageName)
		}
	})
}

// Feature: vulnscanner, Property 13: OSV error resilience
// Any OSV API failure yields a partial output with ScanError set — never an RPC error.
func TestProperty_OSVErrorResilience(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		status := rapid.SampledFrom([]int{400, 401, 403, 404, 429, 500, 502, 503}).Draw(t, "status")

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		defer server.Close()

		h := NewVulnScannerHandler(NewOSVClientWithURL(server.URL), nil)
		params, _ := json.Marshal(VulnScannerInput{
			Manifest:  `{"dependencies":{"lodash":"4.17.0"}}`,
			Ecosystem: "npm",
		})

		result, err := h.Handle(context.Background(), params)
		if err != nil {
			t.Fatalf("Handle must not return an RPC error on OSV failure (status %d), got: %v", status, err)
		}
		out, ok := result.(*VulnScannerOutput)
		if !ok {
			t.Fatalf("unexpected result type: %T", result)
		}
		if out.ScanError == "" {
			t.Errorf("expected ScanError set for OSV status %d", status)
		}
		if out.TotalDeps != 1 {
			t.Errorf("TotalDeps = %d, want 1 even on OSV failure", out.TotalDeps)
		}
	})
}
