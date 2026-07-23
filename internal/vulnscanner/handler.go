package vulnscanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/logging"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// Execution guardrails for the Vuln-Scanner handler.
const (
	// maxManifestBytes rejects oversized manifests to prevent memory exhaustion.
	maxManifestBytes = 5 * 1024 * 1024 // 5 MB
	// defaultEnrichTimeout bounds a single LLM enrichment call.
	defaultEnrichTimeout = 1500 * time.Millisecond
	// defaultMaxConcurrentEnrich caps concurrent LLM calls GLOBALLY across requests.
	defaultMaxConcurrentEnrich = 5
	// defaultMaxEnrichPerRequest caps how many findings a single request enriches.
	defaultMaxEnrichPerRequest = 5
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
	// RequestID correlates this response with the asynchronous enrichment
	// notifications it triggers. Empty when no enrichment runs.
	RequestID string `json:"request_id,omitempty"`
}

// FindingEnrichment is the payload delivered asynchronously for a single finding
// once its LLM explanation completes.
type FindingEnrichment struct {
	RequestID     string `json:"request_id"`
	FindingIndex  int    `json:"finding_index"`
	PackageName   string `json:"package_name"`
	CVEID         string `json:"cve_id"`
	AIExplanation string `json:"ai_explanation"`
}

// VulnScannerHandler wires together the manifest parser, OSV client, and optional
// asynchronous LLM enrichment to provide the complete vuln-scanner MCP tool.
type VulnScannerHandler struct {
	osvClient *OSVClient
	llm       llm.LLMBackend // may be nil; nil means no enrichment
	notifier  rpc.Notifier   // may be nil; nil means no enrichment

	enrichTimeout time.Duration
	maxPerRequest int
	globalSem     chan struct{} // bounds concurrent LLM calls across all requests

	// Lifecycle: baseCtx is cancelled on Shutdown; inflight tracks every
	// background enrichment goroutine so shutdown can drain them.
	baseCtx    context.Context
	baseCancel context.CancelFunc
	inflight   sync.WaitGroup

	logger *slog.Logger
}

// NewVulnScannerHandler creates a new VulnScannerHandler. llmBackend may be nil.
func NewVulnScannerHandler(osvClient *OSVClient, llmBackend llm.LLMBackend) *VulnScannerHandler {
	baseCtx, cancel := context.WithCancel(context.Background())
	return &VulnScannerHandler{
		osvClient:     osvClient,
		llm:           llmBackend,
		enrichTimeout: defaultEnrichTimeout,
		maxPerRequest: defaultMaxEnrichPerRequest,
		globalSem:     make(chan struct{}, defaultMaxConcurrentEnrich),
		baseCtx:       baseCtx,
		baseCancel:    cancel,
		logger:        logging.ModuleLogger("vuln-scanner"),
	}
}

// SetNotifier wires the transport (or any rpc.Notifier) used to push asynchronous
// enrichment notifications. Called once at startup. Nil notifier disables enrichment.
func (h *VulnScannerHandler) SetNotifier(n rpc.Notifier) {
	h.notifier = n
}

// Shutdown cancels in-flight background enrichment and waits for it to unwind.
func (h *VulnScannerHandler) Shutdown() {
	h.baseCancel()
	h.inflight.Wait()
}

// waitBackground blocks until all in-flight enrichment goroutines finish.
func (h *VulnScannerHandler) waitBackground() {
	h.inflight.Wait()
}

// Handle processes a vulnscanner/scan request. It returns the findings
// immediately; LLM explanations (if enabled) are delivered asynchronously via
// notifications and are NOT part of the initial response.
func (h *VulnScannerHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input VulnScannerInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}
	if input.Manifest == "" {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("manifest is required"))
	}
	if input.Ecosystem == "" {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("ecosystem is required"))
	}
	if len(input.Manifest) > maxManifestBytes {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("manifest exceeds maximum size of 5MB"))
	}

	start := time.Now()
	h.logger.Info("scan_started", "event", "scan_started", "ecosystem", input.Ecosystem)

	// Parse manifest into dependencies.
	deps, err := ParseManifest(input.Manifest, input.Ecosystem)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}

	output := &VulnScannerOutput{TotalDeps: len(deps), Findings: []VulnFinding{}}

	// Query OSV. Failures are captured in ScanError, never propagated as RPC errors.
	vulnMap, err := h.osvClient.QueryBatch(ctx, deps)
	if err != nil {
		output.ScanError = err.Error()
		h.logger.Warn("scan_completed",
			"event", "scan_completed", "total_deps", output.TotalDeps,
			"vuln_count", 0, "scan_error", true, "latency_ms", time.Since(start).Milliseconds())
		return output, nil
	}

	// Map vulnerabilities to findings.
	for pkgName, vulns := range vulnMap {
		for _, vuln := range vulns {
			output.Findings = append(output.Findings, mapOSVToFinding(pkgName, vuln))
		}
	}
	// Deterministic ordering: highest severity first.
	sort.SliceStable(output.Findings, func(i, j int) bool {
		return output.Findings[i].Severity > output.Findings[j].Severity
	})
	output.VulnCount = len(output.Findings)

	// Kick off async enrichment for the top findings — only when an LLM backend
	// and a notifier are available AND the request carries a client session.
	// Without a session id there is no delivery target, and emitting would
	// broadcast one caller's enrichment to every connected client, so we skip it.
	clientID := rpc.ClientID(ctx)
	if h.llm != nil && h.notifier != nil && len(output.Findings) > 0 && clientID != "" {
		requestID := newRequestID()
		output.RequestID = requestID
		h.startBackgroundEnrichment(clientID, requestID, output.Findings)
	}

	h.logger.Info("scan_completed",
		"event", "scan_completed", "total_deps", output.TotalDeps,
		"vuln_count", output.VulnCount, "scan_error", false, "latency_ms", time.Since(start).Milliseconds())

	return output, nil
}

// startBackgroundEnrichment enriches the top-N findings (by severity) in the
// background and returns immediately. Each completed enrichment is pushed to the
// originating client as a JSON-RPC notification carrying the shared request_id.
func (h *VulnScannerHandler) startBackgroundEnrichment(clientID, requestID string, findings []VulnFinding) {
	if clientID == "" { // defense in depth: never enrich without a delivery target
		return
	}
	n := h.maxPerRequest
	if n > len(findings) {
		n = len(findings)
	}

	// Detached, handler-scoped context (cancelled on Shutdown), re-tagged with the
	// originating client id so notifications route back to it.
	baseCtx := rpc.WithClientID(h.baseCtx, clientID)

	for i := 0; i < n; i++ {
		h.inflight.Add(1)
		go func(idx int, f VulnFinding) {
			defer h.inflight.Done()

			select {
			case h.globalSem <- struct{}{}:
			case <-h.baseCtx.Done():
				return // shutting down
			}
			defer func() { <-h.globalSem }()

			callCtx, cancel := context.WithTimeout(baseCtx, h.enrichTimeout)
			defer cancel()

			resp, err := h.llm.Complete(callCtx, h.buildPrompt(f))
			if err != nil || resp == nil || resp.Text == "" {
				// Silently drop this finding's enrichment — the response already shipped.
				h.logger.Warn("enrichment_dropped",
					"event", "enrichment_dropped", "cve_id", f.CVEID, "package", f.PackageName, "error", err)
				return
			}
			h.emitEnrichment(baseCtx, requestID, idx, f, resp.Text)
		}(i, findings[i])
	}
}

// emitEnrichment pushes a single finding's enrichment as a JSON-RPC
// "notifications/message" notification (MCP logging shape).
func (h *VulnScannerHandler) emitEnrichment(ctx context.Context, requestID string, idx int, f VulnFinding, explanation string) {
	params := map[string]interface{}{
		"level":  "info",
		"logger": "vulnscanner/scan",
		"data": FindingEnrichment{
			RequestID:     requestID,
			FindingIndex:  idx,
			PackageName:   f.PackageName,
			CVEID:         f.CVEID,
			AIExplanation: explanation,
		},
	}
	if err := h.notifier.Send(ctx, rpc.NewNotification("notifications/message", params)); err != nil {
		h.logger.Warn("notification_send_failed",
			"event", "notification_send_failed", "cve_id", f.CVEID, "error", err.Error())
	}
}

// buildPrompt constructs the LLM prompt for a finding. To keep Bedrock usage
// ultra-efficient, it includes ONLY the CVE id, package, severity, affected range
// and fixed version — never raw OSV JSON.
func (h *VulnScannerHandler) buildPrompt(f VulnFinding) llm.Prompt {
	return llm.Prompt{
		System: "You are a security expert. Provide a brief, actionable explanation of the vulnerability in under 2 sentences.",
		User: fmt.Sprintf(
			"CVE: %s\nPackage: %s\nSeverity: %.1f\nAffected range: %s\nFixed in: %s",
			f.CVEID, f.PackageName, f.Severity, f.AffectedRange, f.FixedVersion,
		),
	}
}

// newRequestID returns a short random hex id used to correlate an analyze
// response with its asynchronous enrichment notifications.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// mapOSVToFinding converts an OSVVulnerability into a VulnFinding.
func mapOSVToFinding(pkgName string, vuln OSVVulnerability) VulnFinding {
	finding := VulnFinding{
		PackageName: pkgName,
		CVEID:       vuln.ID,
		Severity:    parseSeverityScore(vuln.Severity),
	}
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
func parseSeverityScore(severities []OSVSeverity) float64 {
	for _, sev := range severities {
		if score := extractCVSSScore(sev.Score); score > 0 {
			return score
		}
	}
	return 0.0
}

// extractCVSSScore extracts a numeric score from a CVSS vector or direct number.
func extractCVSSScore(vector string) float64 {
	if vector == "" {
		return 0.0
	}
	var score float64
	if _, err := fmt.Sscanf(vector, "%f", &score); err == nil && score > 0 && score <= 10 {
		return score
	}
	if strings.Contains(vector, "CVSS:") {
		return estimateFromCVSSVector(vector)
	}
	return 0.0
}

// estimateFromCVSSVector provides a rough severity score based on CVSS components.
func estimateFromCVSSVector(vector string) float64 {
	highCount := strings.Count(vector, ":H")
	medCount := strings.Count(vector, ":M")
	switch {
	case highCount >= 3:
		return 9.0
	case highCount >= 2:
		return 7.5
	case highCount >= 1 || medCount >= 2:
		return 5.5
	case medCount >= 1:
		return 3.5
	default:
		return 2.0
	}
}

// buildRangeInfo constructs a human-readable affected range and extracts the
// fixed version from OSV range events.
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
	if introduced != "" && fixedVersion != "" {
		affectedRange = fmt.Sprintf(">=%s, <%s", introduced, fixedVersion)
	} else if introduced != "" {
		affectedRange = fmt.Sprintf(">=%s", introduced)
	}
	return affectedRange, fixedVersion
}

// RegisterVulnScanner registers the vulnscanner/scan tool handler with the RPC dispatcher.
func RegisterVulnScanner(d *rpc.Dispatcher, handler *VulnScannerHandler) {
	d.Register("vulnscanner/scan", handler.Handle)
}
