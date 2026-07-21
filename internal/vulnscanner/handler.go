package vulnscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// VulnFinding represents a single vulnerability found during scanning.
type VulnFinding struct {
	PackageName   string  `json:"package_name"`
	CVEID         string  `json:"cve_id"`
	Severity      float64 `json:"severity_score"`
	AffectedRange string  `json:"affected_range"`
	FixedVersion  string  `json:"fixed_version"`
	Explanation   string  `json:"explanation,omitempty"`
}

// VulnScannerInput represents the input parameters for the vulnscanner/scan tool.
type VulnScannerInput struct {
	Manifest  string `json:"manifest"`
	Ecosystem string `json:"ecosystem"` // "npm" | "pip"
}

// VulnScannerOutput represents the output of the vulnscanner/scan tool.
type VulnScannerOutput struct {
	Findings  []VulnFinding `json:"findings"`
	TotalDeps int           `json:"total_deps"`
	VulnCount int           `json:"vuln_count"`
	ScanError string        `json:"scan_error,omitempty"`
}

// VulnScannerHandler wires together the manifest parser, OSV client, and LLM
// to provide the complete vuln-scanner MCP tool.
type VulnScannerHandler struct {
	osvClient *OSVClient
	llm       llm.LLMBackend // may be nil
}

// NewVulnScannerHandler creates a new VulnScannerHandler with the given components.
// llmBackend may be nil if LLM is not available.
func NewVulnScannerHandler(osvClient *OSVClient, llmBackend llm.LLMBackend) *VulnScannerHandler {
	return &VulnScannerHandler{
		osvClient: osvClient,
		llm:       llmBackend,
	}
}

// Handle processes a vulnscanner/scan request.
// Flow:
//  1. Parse params as VulnScannerInput
//  2. Call ParseManifest to get dependencies
//  3. Call osvClient.QueryBatch to get vulnerabilities
//  4. For each vulnerability, create a VulnFinding
//  5. If LLM is available, generate human-readable explanations
//  6. Return VulnScannerOutput
func (h *VulnScannerHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input VulnScannerInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if input.Manifest == "" {
		return nil, fmt.Errorf("invalid params: manifest is required")
	}

	if input.Ecosystem == "" {
		return nil, fmt.Errorf("invalid params: ecosystem is required")
	}

	// Step 1: Parse manifest to get dependencies
	deps, err := ParseManifest(input.Manifest, input.Ecosystem)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	output := &VulnScannerOutput{
		TotalDeps: len(deps),
		Findings:  []VulnFinding{},
	}

	// Step 2: Query OSV for vulnerabilities
	vulnMap, err := h.osvClient.QueryBatch(ctx, deps)
	if err != nil {
		// On OSV error, set ScanError but don't fail the entire request
		output.ScanError = err.Error()
		return output, nil
	}

	// Step 3: Map vulnerabilities to VulnFinding structs
	for pkgName, vulns := range vulnMap {
		for _, vuln := range vulns {
			finding := mapOSVToFinding(pkgName, vuln)
			output.Findings = append(output.Findings, finding)
		}
	}
	output.VulnCount = len(output.Findings)

	// Step 4: If LLM is available, generate explanations
	if h.llm != nil && len(output.Findings) > 0 {
		h.enrichWithExplanations(ctx, output.Findings)
	}

	return output, nil
}

// mapOSVToFinding converts an OSVVulnerability into a VulnFinding.
func mapOSVToFinding(pkgName string, vuln OSVVulnerability) VulnFinding {
	finding := VulnFinding{
		PackageName: pkgName,
		CVEID:       vuln.ID,
		Severity:    parseSeverityScore(vuln.Severity),
	}

	// Extract affected range and fixed version from affected ranges
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			affectedRange, fixedVersion := buildRangeInfo(r.Events)
			if affectedRange != "" {
				finding.AffectedRange = affectedRange
			}
			if fixedVersion != "" {
				finding.FixedVersion = fixedVersion
			}
		}
	}

	return finding
}

// parseSeverityScore extracts a numeric severity score from OSV severity data.
// It looks for a CVSS_V3 score first, falls back to CVSS_V2, then 0.0.
func parseSeverityScore(severities []OSVSeverity) float64 {
	for _, sev := range severities {
		score := extractCVSSScore(sev.Score)
		if score > 0 {
			return score
		}
	}
	return 0.0
}

// extractCVSSScore extracts a numeric score from a CVSS vector string.
// CVSS vectors look like: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
// Some responses include a direct score like "9.8" or a vector with score appended.
func extractCVSSScore(vector string) float64 {
	if vector == "" {
		return 0.0
	}

	// Try parsing as a direct numeric score
	var score float64
	if _, err := fmt.Sscanf(vector, "%f", &score); err == nil && score > 0 && score <= 10 {
		return score
	}

	// Map based on CVSS severity indicators in the vector
	// This is a simplified heuristic based on the impact metrics
	if strings.Contains(vector, "CVSS:") {
		return estimateFromCVSSVector(vector)
	}

	return 0.0
}

// estimateFromCVSSVector provides a rough severity score based on CVSS vector components.
func estimateFromCVSSVector(vector string) float64 {
	// Count high-impact indicators
	highCount := strings.Count(vector, ":H")
	medCount := strings.Count(vector, ":M")

	switch {
	case highCount >= 3:
		return 9.0 // Critical
	case highCount >= 2:
		return 7.5 // High
	case highCount >= 1 || medCount >= 2:
		return 5.5 // Medium
	case medCount >= 1:
		return 3.5 // Low
	default:
		return 2.0 // Informational
	}
}

// buildRangeInfo constructs a human-readable affected range string and extracts
// the fixed version from OSV range events.
func buildRangeInfo(events []OSVEvent) (affectedRange string, fixedVersion string) {
	var introduced string

	for _, event := range events {
		if event.Introduced != "" {
			introduced = event.Introduced
		}
		if event.Fixed != "" {
			fixedVersion = event.Fixed
		}
	}

	// Build affected range string
	if introduced != "" && fixedVersion != "" {
		affectedRange = fmt.Sprintf(">=%s, <%s", introduced, fixedVersion)
	} else if introduced != "" {
		affectedRange = fmt.Sprintf(">=%s", introduced)
	}

	return affectedRange, fixedVersion
}

// enrichWithExplanations uses the LLM to generate human-readable explanations
// for each finding. Errors are silently ignored (explanation stays empty).
func (h *VulnScannerHandler) enrichWithExplanations(ctx context.Context, findings []VulnFinding) {
	for i := range findings {
		prompt := llm.Prompt{
			System: "You are a security expert. Provide a brief, actionable explanation of a vulnerability.",
			User: fmt.Sprintf(
				"Explain the vulnerability %s affecting package %s (severity: %.1f). "+
					"Affected versions: %s. Fixed in: %s. "+
					"Keep the explanation under 2 sentences.",
				findings[i].CVEID,
				findings[i].PackageName,
				findings[i].Severity,
				findings[i].AffectedRange,
				findings[i].FixedVersion,
			),
		}

		resp, err := h.llm.Complete(ctx, prompt)
		if err == nil && resp != nil && resp.Text != "" {
			findings[i].Explanation = resp.Text
		}
	}
}

// RegisterVulnScanner registers the vulnscanner/scan tool handler with the RPC dispatcher.
func RegisterVulnScanner(d *rpc.Dispatcher, handler *VulnScannerHandler) {
	d.Register("vulnscanner/scan", handler.Handle)
}
