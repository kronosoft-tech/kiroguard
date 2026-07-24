package piiguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/logging"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

const (
	defaultSeverityThreshold = "low"
	defaultMaxFileSizeMB     = 2
	defaultEntropyThreshold  = 4.5
	defaultEnrichTimeout     = 5 * time.Second
	defaultScanTimeout       = 15 * time.Second
	defaultMaxConcurrent     = 3
	defaultMetricsInterval   = 60 * time.Second
)

type PIIGuardOptions struct {
	llm              llm.LLMBackend
	notifier         rpc.Notifier
	metrics          *Metrics
	severityThreshold string
	maxFileSizeMB    int
	entropyThreshold float64
	enrichTimeout    time.Duration
	scanTimeout      time.Duration
	maxConcurrent    int
	metricsInterval  time.Duration
}

type PIIGuardOption func(*PIIGuardOptions)

func WithLLM(llmBackend llm.LLMBackend) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		o.llm = llmBackend
	}
}

func WithNotifier(n rpc.Notifier) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		o.notifier = n
	}
}

func WithMetrics(m *Metrics) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if m != nil {
			o.metrics = m
		}
	}
}

func WithSeverityThreshold(s string) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if s != "" {
			o.severityThreshold = s
		}
	}
}

func WithMaxFileSizeMB(n int) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if n > 0 {
			o.maxFileSizeMB = n
		}
	}
}

func WithEntropyThreshold(f float64) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if f > 0 {
			o.entropyThreshold = f
		}
	}
}

func WithEnrichTimeout(d time.Duration) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if d > 0 {
			o.enrichTimeout = d
		}
	}
}

func WithScanTimeout(d time.Duration) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if d > 0 {
			o.scanTimeout = d
		}
	}
}

func WithMaxConcurrent(n int) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if n > 0 {
			o.maxConcurrent = n
		}
	}
}

func WithMetricsInterval(d time.Duration) PIIGuardOption {
	return func(o *PIIGuardOptions) {
		if d > 0 {
			o.metricsInterval = d
		}
	}
}

type PIIGuardHandler struct {
	llm      llm.LLMBackend
	notifier rpc.Notifier

	opts PIIGuardOptions

	baseCtx    context.Context
	baseCancel context.CancelFunc
	inflight   sync.WaitGroup
	globalSem  chan struct{}

	metrics *Metrics
	logger  *slog.Logger
}

func NewPIIGuardHandler(opts ...PIIGuardOption) *PIIGuardHandler {
	baseCtx, cancel := context.WithCancel(context.Background())
	o := PIIGuardOptions{
		severityThreshold: defaultSeverityThreshold,
		maxFileSizeMB:     defaultMaxFileSizeMB,
		entropyThreshold:  defaultEntropyThreshold,
		enrichTimeout:     defaultEnrichTimeout,
		scanTimeout:       defaultScanTimeout,
		maxConcurrent:     defaultMaxConcurrent,
		metricsInterval:   defaultMetricsInterval,
	}
	for _, opt := range opts {
		opt(&o)
	}

	h := &PIIGuardHandler{
		opts:       o,
		baseCtx:    baseCtx,
		baseCancel: cancel,
		metrics:    o.metrics,
		logger:     logging.ModuleLogger("pii-guard"),
	}
	if h.metrics == nil {
		h.metrics = &Metrics{}
	}
	if o.llm != nil {
		h.llm = o.llm
	}
	if o.notifier != nil {
		h.notifier = o.notifier
	}
	h.globalSem = make(chan struct{}, o.maxConcurrent)
	return h
}

func (h *PIIGuardHandler) SetNotifier(n rpc.Notifier) {
	h.notifier = n
}

func (h *PIIGuardHandler) MetricsSnapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ScansTotal:          h.metrics.ScansTotal.Load(),
		FindingsTotal:       h.metrics.FindingsTotal.Load(),
		CriticalFindings:    h.metrics.CriticalFindings.Load(),
		VerificationsOK:     h.metrics.VerificationsOK.Load(),
		VerificationsFailed: h.metrics.VerificationsFailed.Load(),
	}
}

func (h *PIIGuardHandler) StartMetricsReporter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = h.opts.metricsInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.reportMetrics()
			return
		case <-ticker.C:
			h.reportMetrics()
		}
	}
}

func (h *PIIGuardHandler) reportMetrics() {
	m := h.MetricsSnapshot()
	h.logger.Info("metrics_report",
		"event", "metrics_report",
		"scans_total", m.ScansTotal,
		"findings_total", m.FindingsTotal,
		"critical_findings", m.CriticalFindings,
		"verifications_ok", m.VerificationsOK,
		"verifications_failed", m.VerificationsFailed)
}

func (h *PIIGuardHandler) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.inflight.Wait()
		close(done)
	}()

	select {
	case <-done:
		h.baseCancel()
		return nil
	case <-ctx.Done():
		h.baseCancel()
		<-done
		return ctx.Err()
	}
}

func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func (h *PIIGuardHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p PIIParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}

	if p.DirectoryPath == "" {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("directory_path is required"))
	}

	stat, err := os.Stat(p.DirectoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("directory not found: "+p.DirectoryPath))
		}
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("path is not a directory: "+p.DirectoryPath))
	}

	threshold := h.opts.severityThreshold
	if p.SeverityThreshold != "" {
		threshold = p.SeverityThreshold
	}
	threshold = strings.ToLower(threshold)
	switch threshold {
	case "low", "medium", "high", "critical":
	default:
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("severity_threshold must be one of: low, medium, high, critical"))
	}

	entropyCheck := true
	if p.EntropyCheck != nil {
		entropyCheck = *p.EntropyCheck
	}

	start := time.Now()
	h.metrics.ScansTotal.Add(1)
	h.logger.Info("scan_started", "event", "scan_started", "target", p.DirectoryPath)

	scanCtx, scanCancel := context.WithTimeout(ctx, h.opts.scanTimeout)
	defer scanCancel()

	patterns := GetPatterns(p.Patterns)
	maxBytes := int64(h.opts.maxFileSizeMB) * 1024 * 1024

	findings, summary, scanErr := ScanFiles(scanCtx, p.DirectoryPath, patterns, entropyCheck, maxBytes)
	if scanErr != nil {
		return nil, fmt.Errorf("scan files: %w", scanErr)
	}

	if threshold != "low" {
		findings = filterBySeverity(findings, threshold)
		summary.TotalFindings = len(findings)
		summary.BySeverity = countBySeverity(findings)
		summary.ByPatternType = countByPatternType(findings)
	}
	summary.ScanTimeMs = time.Since(start).Milliseconds()

	h.metrics.FindingsTotal.Add(int64(len(findings)))
	for _, f := range findings {
		if f.Severity == "critical" {
			h.metrics.CriticalFindings.Add(1)
		}
	}

	clientID := rpc.ClientID(ctx)
	hasCriticalHigh := false
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			hasCriticalHigh = true
			break
		}
	}
	enrichmentPossible := h.llm != nil && h.notifier != nil
	enrichmentWillRun := enrichmentPossible && clientID != "" && hasCriticalHigh

	var requestID string
	if enrichmentWillRun {
		requestID = newRequestID()
		h.startBackgroundVerification(ctx, clientID, requestID, findings)
	}

	h.logger.Info("scan_completed",
		"event", "scan_completed",
		"target", p.DirectoryPath,
		"findings", len(findings),
		"files_scanned", summary.FilesScanned,
		"latency_ms", summary.ScanTimeMs)

	return &PIIResponse{
		Findings:   findings,
		Summary:    *summary,
		ScanTimeMs: summary.ScanTimeMs,
		RequestID:  requestID,
	}, nil
}

func (h *PIIGuardHandler) startBackgroundVerification(ctx context.Context, clientID, requestID string, findings []PIIFinding) {
	baseCtx := rpc.WithClientID(h.baseCtx, clientID)

	h.inflight.Add(1)
	go func() {
		defer h.inflight.Done()

		select {
		case h.globalSem <- struct{}{}:
		case <-h.baseCtx.Done():
			return
		}
		defer func() { <-h.globalSem }()

		verdicts := h.runVerification(baseCtx, findings)

		result := VerificationResult{
			RequestID:   requestID,
			Verdicts:    verdicts,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}

		if err := h.emitVerification(baseCtx, result); err != nil {
			h.metrics.VerificationsFailed.Add(1)
			return
		}
		h.metrics.VerificationsOK.Add(1)
	}()
}

func (h *PIIGuardHandler) runVerification(ctx context.Context, findings []PIIFinding) []FindingVerdict {
	var verdicts []FindingVerdict
	grouped := groupByFile(findings)

	for _, group := range grouped {
		select {
		case <-ctx.Done():
			return verdicts
		default:
		}

		vd, err := h.verifyGroup(ctx, group)
		if err != nil {
			h.metrics.VerificationsFailed.Add(1)
			h.logger.Warn("llm_verification_failed",
				"event", "llm_fallback_triggered",
				"reason", "error",
				"file", group[0].FilePath)
			continue
		}
		verdicts = append(verdicts, vd...)
	}
	return verdicts
}

func (h *PIIGuardHandler) verifyGroup(ctx context.Context, group []PIIFinding) ([]FindingVerdict, error) {
	callCtx, cancel := context.WithTimeout(ctx, h.opts.enrichTimeout)
	defer cancel()

	prompt := buildVerificationPrompt(group)
	resp, err := h.llm.Complete(callCtx, prompt)
	if err != nil {
		return nil, fmt.Errorf("llm complete: %w", err)
	}
	if resp == nil || resp.Text == "" {
		return nil, fmt.Errorf("empty llm response")
	}
	return parseVerdicts(resp.Text, group)
}

func (h *PIIGuardHandler) emitVerification(ctx context.Context, result VerificationResult) error {
	params := map[string]interface{}{
		"level":  "info",
		"logger": "piiguard/scan",
		"data":   result,
	}
	return h.notifier.Send(ctx, rpc.NewNotification("notifications/message", params))
}

func groupByFile(findings []PIIFinding) [][]PIIFinding {
	groups := map[string][]PIIFinding{}
	order := []string{}
	for _, f := range findings {
		if _, ok := groups[f.FilePath]; !ok {
			order = append(order, f.FilePath)
		}
		groups[f.FilePath] = append(groups[f.FilePath], f)
	}
	result := make([][]PIIFinding, len(order))
	for i, path := range order {
		result[i] = groups[path]
	}
	return result
}

func buildVerificationPrompt(group []PIIFinding) llm.Prompt {
	var b strings.Builder
	fmt.Fprintf(&b, "Verify if these PII findings are true or false positives. Respond with JSON array: [{\"pattern_type\": \"...\", \"is_true_positive\": true/false, \"reason\": \"...\"}]\n\n")
	for _, f := range group {
		fmt.Fprintf(&b, "- pattern_type=%q severity=%q context=%q match_sample=%q\n", f.PatternType, f.Severity, f.Context, f.MatchSample)
	}
	return llm.Prompt{
		System: "You are a PII verification assistant. Determine if each finding is a true positive (real PII exposure) or false positive (safe context). Be conservative: flag as false positive if unsure.",
		User:   b.String(),
	}
}

func parseVerdicts(text string, group []PIIFinding) ([]FindingVerdict, error) {
	var raw []struct {
		PatternType    string `json:"pattern_type"`
		IsTruePositive bool   `json:"is_true_positive"`
		Reason         string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("parse verdicts: %w", err)
	}

	verdicts := make([]FindingVerdict, 0, len(raw))
	for _, r := range raw {
		for _, f := range group {
			if f.PatternType == r.PatternType {
				verdicts = append(verdicts, FindingVerdict{
					FilePath:       f.FilePath,
					LineNumber:     f.LineNumber,
					PatternType:    r.PatternType,
					IsTruePositive: r.IsTruePositive,
					LLMReason:      r.Reason,
				})
				break
			}
		}
	}
	return verdicts, nil
}

func RegisterPIIGuard(d *rpc.Dispatcher, handler *PIIGuardHandler) {
	d.Register("piiguard/scan", handler.Handle)
}

func filterBySeverity(findings []PIIFinding, threshold string) []PIIFinding {
	order := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	minLevel := order[threshold]
	var out []PIIFinding
	for _, f := range findings {
		if level, ok := order[f.Severity]; ok && level >= minLevel {
			out = append(out, f)
		}
	}
	return out
}

func countBySeverity(findings []PIIFinding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}

func countByPatternType(findings []PIIFinding) map[string]int {
	m := map[string]int{}
	for _, f := range findings {
		m[f.PatternType]++
	}
	return m
}
