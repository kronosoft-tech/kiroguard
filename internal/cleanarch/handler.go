package cleanarch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/logging"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// Execution guardrails for the Clean-Arch handler.
const (
	// defaultScanTimeout bounds the whole analysis (scan + evaluation +
	// enrichment) so a slow LLM backend can never hang the MCP response.
	defaultScanTimeout = 3 * time.Second
	// defaultEnrichTimeout bounds a single LLM enrichment call.
	defaultEnrichTimeout = 1500 * time.Millisecond
	// defaultMaxConcurrentEnrich caps concurrent LLM calls to avoid a large
	// fan-out (throttling / cost) on projects with many violations. This limit is
	// GLOBAL (shared across all in-flight requests), not per-request.
	defaultMaxConcurrentEnrich = 5
	// defaultMaxEnrichmentsPerRequest caps how many violations a single request
	// will enrich, protecting cost/latency when a file has many violations.
	defaultMaxEnrichmentsPerRequest = 25
	// defaultMetricsInterval is the fallback cadence for the periodic metrics report.
	defaultMetricsInterval = 60 * time.Second
)

// Metrics holds atomic counters for Clean-Arch, suitable for periodic export to
// CloudWatch / a metrics sink. All fields are updated with atomic operations.
type Metrics struct {
	ScansTotal        atomic.Int64
	ViolationsTotal   atomic.Int64
	EnrichmentsOK     atomic.Int64
	EnrichmentsFailed atomic.Int64
}

// MetricsSnapshot is an immutable point-in-time copy of the counters.
type MetricsSnapshot struct {
	ScansTotal        int64 `json:"scans_total"`
	ViolationsTotal   int64 `json:"violations_total"`
	EnrichmentsOK     int64 `json:"enrichments_ok"`
	EnrichmentsFailed int64 `json:"enrichments_failed"`
}

// Option configures a CleanArchHandler at construction time.
type Option func(*CleanArchHandler)

// WithScanTimeout overrides the AST scan deadline (default 3s).
func WithScanTimeout(d time.Duration) Option {
	return func(h *CleanArchHandler) {
		if d > 0 {
			h.scanTimeout = d
		}
	}
}

// WithEnrichTimeout overrides the per-LLM-call deadline (default 1.5s).
func WithEnrichTimeout(d time.Duration) Option {
	return func(h *CleanArchHandler) {
		if d > 0 {
			h.enrichTimeout = d
		}
	}
}

// WithMaxConcurrent overrides the GLOBAL max concurrent LLM calls (default 5).
func WithMaxConcurrent(n int) Option {
	return func(h *CleanArchHandler) {
		if n > 0 {
			h.maxConcurrent = n
		}
	}
}

// WithMaxEnrichmentsPerRequest overrides the per-request enrichment cap (default 25).
func WithMaxEnrichmentsPerRequest(n int) Option {
	return func(h *CleanArchHandler) {
		if n > 0 {
			h.maxPerRequest = n
		}
	}
}

// CleanArchInput represents the input parameters for the cleanarch/analyze tool.
type CleanArchInput struct {
	DirectoryPath string `json:"directory_path"`
	RulesFile     string `json:"rules_file,omitempty"`
}

// EnrichedViolation extends an ArchViolation with optional, advisory
// LLM-generated context. All enrichment fields are advisory only and are never
// applied to disk — this module is strictly READ-ONLY.
type EnrichedViolation struct {
	ArchViolation
	AIExplanation string `json:"ai_explanation,omitempty"`
	SuggestedFix  string `json:"suggested_fix_diff,omitempty"`
	Fallback      bool   `json:"fallback,omitempty"`
}

// CleanArchOutput represents the output of the cleanarch/analyze tool.
type CleanArchOutput struct {
	Violations []EnrichedViolation `json:"violations"`
	TotalEdges int                 `json:"total_edges"`
	Message    string              `json:"message"`
	// RequestID correlates this response with the asynchronous enrichment
	// notifications it will trigger. Empty when no enrichment runs.
	RequestID string `json:"request_id,omitempty"`
}

// CleanArchHandler wires together AST analysis, rule evaluation, and optional
// LLM enrichment to provide the complete Clean-Arch MCP tool.
// This handler is READ-ONLY: it never writes, modifies, or deletes any files.
type CleanArchHandler struct {
	defaultRules []Rule
	llmBackend   llm.LLMBackend // may be nil; nil means enrichment is skipped
	notifier     rpc.Notifier   // may be nil; nil means enrichment is skipped

	// Execution guardrails. Defaulted in the constructor; overridable via Options.
	scanTimeout   time.Duration // AST scan deadline
	enrichTimeout time.Duration // per-LLM-call deadline
	maxConcurrent int           // GLOBAL max concurrent LLM enrichment calls
	maxPerRequest int           // max violations enriched per request

	// globalSem bounds concurrent LLM calls across ALL in-flight requests.
	globalSem chan struct{}

	// Lifecycle: baseCtx is cancelled on Shutdown; inflight tracks every
	// background enrichment goroutine so shutdown can drain them.
	baseCtx    context.Context
	baseCancel context.CancelFunc
	inflight   sync.WaitGroup

	// metrics holds atomic operational counters.
	metrics *Metrics

	// logger emits structured (CloudWatch-friendly) events, tagged module=clean-arch.
	logger *slog.Logger
}

// ViolationEnrichment is the payload delivered asynchronously for a single
// violation once its LLM enrichment completes.
type ViolationEnrichment struct {
	// RequestID matches CleanArchOutput.RequestID so a client can correlate this
	// notification with the analyze request that produced it.
	RequestID      string `json:"request_id"`
	ViolationIndex int    `json:"violation_index"`
	FilePath       string `json:"file_path"`
	Import         string `json:"import"`
	AIExplanation  string `json:"ai_explanation"`
	SuggestedFix   string `json:"suggested_fix_diff,omitempty"`
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

// SetNotifier wires the transport (or any rpc.Notifier) used to push asynchronous
// enrichment notifications to the client. It is typically called once at startup,
// after the transport is created. If no notifier is set, enrichment is skipped.
func (h *CleanArchHandler) SetNotifier(n rpc.Notifier) {
	h.notifier = n
}

// MetricsSnapshot returns a point-in-time copy of the operational counters.
func (h *CleanArchHandler) MetricsSnapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ScansTotal:        h.metrics.ScansTotal.Load(),
		ViolationsTotal:   h.metrics.ViolationsTotal.Load(),
		EnrichmentsOK:     h.metrics.EnrichmentsOK.Load(),
		EnrichmentsFailed: h.metrics.EnrichmentsFailed.Load(),
	}
}

// StartMetricsReporter periodically emits a structured "metrics_report" event
// until ctx is cancelled, then emits one final report. Run it in its own
// goroutine; CloudWatch metric filters can extract the counters from these logs.
func (h *CleanArchHandler) StartMetricsReporter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultMetricsInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			h.reportMetrics() // final flush on shutdown
			return
		case <-ticker.C:
			h.reportMetrics()
		}
	}
}

// reportMetrics logs a single point-in-time metrics snapshot.
func (h *CleanArchHandler) reportMetrics() {
	m := h.MetricsSnapshot()
	h.logger.Info("metrics_report",
		"event", "metrics_report",
		"scans_total", m.ScansTotal,
		"violations_total", m.ViolationsTotal,
		"enrichments_ok", m.EnrichmentsOK,
		"enrichments_failed", m.EnrichmentsFailed)
}

// Shutdown gracefully drains in-flight background enrichment. It waits until all
// enrichment goroutines finish or ctx expires; on expiry it cancels them and
// waits for them to observe cancellation before returning ctx.Err().
func (h *CleanArchHandler) Shutdown(ctx context.Context) error {
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
		h.baseCancel() // force-cancel in-flight LLM calls
		<-done         // wait for goroutines to unwind
		return ctx.Err()
	}
}

// waitBackground blocks until all in-flight background enrichment goroutines have
// finished. Safe no-op if none are running.
func (h *CleanArchHandler) waitBackground() {
	h.inflight.Wait()
}

// NewCleanArchHandler creates a new CleanArchHandler with the given default rules,
// an optional LLM backend, and optional configuration Options.
// If defaultRules is nil, DefaultRules() will be used when no rules file is specified.
// If llmBackend is nil, violations are returned without AI enrichment.
func NewCleanArchHandler(defaultRules []Rule, llmBackend llm.LLMBackend, opts ...Option) *CleanArchHandler {
	if defaultRules == nil {
		defaultRules = DefaultRules()
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	h := &CleanArchHandler{
		defaultRules:  defaultRules,
		llmBackend:    llmBackend,
		scanTimeout:   defaultScanTimeout,
		enrichTimeout: defaultEnrichTimeout,
		maxConcurrent: defaultMaxConcurrentEnrich,
		maxPerRequest: defaultMaxEnrichmentsPerRequest,
		baseCtx:       baseCtx,
		baseCancel:    cancel,
		metrics:       &Metrics{},
		logger:        logging.ModuleLogger("clean-arch"),
	}
	for _, opt := range opts {
		opt(h)
	}
	// Global semaphore sized after options are applied.
	h.globalSem = make(chan struct{}, h.maxConcurrent)
	return h
}

// Handle processes a cleanarch/analyze request.
// Flow:
//  1. Parse params as CleanArchInput
//  2. Validate directory_path is not empty
//  3. Load rules from rules_file if provided, otherwise use defaultRules
//  4. Call BuildImportGraph(directoryPath) to get edges
//  5. Call Evaluate(edges, rules) to get violations
//  6. Return CleanArchOutput with violations and summary
//
// This handler is READ-ONLY: it never writes, modifies, or deletes any files.
func (h *CleanArchHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input CleanArchInput
	if err := json.Unmarshal(params, &input); err != nil {
		// Malformed params → Invalid Params (-32602) via rpc.ValidationError.
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}

	if input.DirectoryPath == "" {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("directory_path is required"))
	}

	start := time.Now()
	h.metrics.ScansTotal.Add(1)
	h.logger.Info("scan_started", "event", "scan_started", "target", input.DirectoryPath)

	// Bound the AST scan so a pathologically large tree cannot exceed the
	// deadline: on expiry, partial results are returned with a truncation note.
	scanCtx, cancel := context.WithTimeout(ctx, h.scanTimeout)
	defer cancel()

	// Step 1: Load rules
	rules := h.defaultRules
	if input.RulesFile != "" {
		loadedRules, err := LoadRules(input.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules file: %w", err)
		}
		rules = loadedRules
	}

	// Step 2: Build import graph (read-only AST analysis, cancellable)
	_, edges, err := BuildImportGraphContext(scanCtx, input.DirectoryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze directory: %w", err)
	}

	// Step 3: Evaluate edges against rules
	violations := Evaluate(edges, rules)
	h.metrics.ViolationsTotal.Add(int64(len(violations)))

	// Step 4: Wrap violations for the immediate response. Enrichment is NOT
	// inlined here — the response returns right away with the AST findings.
	enriched := make([]EnrichedViolation, len(violations))
	for i, v := range violations {
		enriched[i] = EnrichedViolation{ArchViolation: v}
	}

	// Step 5: Kick off LLM enrichment in the background (non-blocking) — but only
	// when there is a client session to deliver it to. Without a session id there
	// is no target, and emitting would broadcast one caller's enrichment to every
	// connected client, so enrichment is skipped instead.
	clientID := rpc.ClientID(ctx)
	enrichmentPossible := h.notifier != nil && h.llmBackend != nil && len(violations) > 0
	enrichmentWillRun := enrichmentPossible && clientID != ""

	var requestID string
	if enrichmentWillRun {
		requestID = newRequestID()
		h.startBackgroundEnrichment(clientID, requestID, violations)
	}

	// Step 6: Build message
	message := fmt.Sprintf("Analyzed %d import edges, found %d violation(s)", len(edges), len(enriched))
	if scanCtx.Err() != nil {
		// The scan deadline expired; edges/violations are partial.
		message += " (analysis truncated: scan deadline exceeded)"
	}
	switch {
	case enrichmentWillRun:
		message += fmt.Sprintf("; AI enrichment will be delivered asynchronously via notifications/message (request_id=%s)", requestID)
	case enrichmentPossible: // possible but no session id
		message += "; AI enrichment skipped: open an SSE connection and include its sessionId in the request to receive it"
	}

	h.logger.Info("scan_completed",
		"event", "scan_completed",
		"violations_found", len(enriched),
		"total_edges", len(edges),
		"latency_ms", time.Since(start).Milliseconds())

	return &CleanArchOutput{
		Violations: enriched,
		TotalEdges: len(edges),
		Message:    message,
		RequestID:  requestID,
	}, nil
}

// startBackgroundEnrichment launches LLM enrichment for each violation in the
// background and returns immediately. Completed enrichments are pushed to the
// client via rpc notifications. It is a no-op when there is no notifier, no LLM
// backend, or no violations.
//
// Concurrency is bounded by a semaphore (maxConcurrent) and each call has its own
// deadline (enrichTimeout). The goroutines run on a detached context (the request
// context is already done once Handle returns), bounded by scanTimeout overall.
func (h *CleanArchHandler) startBackgroundEnrichment(clientID, requestID string, violations []ArchViolation) {
	if h.notifier == nil || h.llmBackend == nil || len(violations) == 0 || clientID == "" {
		return
	}

	// Per-request cap: protect cost/latency when a file has many violations.
	if h.maxPerRequest > 0 && len(violations) > h.maxPerRequest {
		violations = violations[:h.maxPerRequest]
	}

	// Detached, handler-scoped context (cancelled on Shutdown), re-tagged with the
	// originating client id so notifications route back to it.
	baseCtx := rpc.WithClientID(h.baseCtx, clientID)

	for i := range violations {
		h.inflight.Add(1)
		go func(idx int, v ArchViolation) {
			defer h.inflight.Done()

			// Acquire a slot from the GLOBAL semaphore (bounded across all requests).
			select {
			case h.globalSem <- struct{}{}:
			case <-h.baseCtx.Done():
				return // shutting down
			}
			defer func() { <-h.globalSem }()

			callCtx, callCancel := context.WithTimeout(baseCtx, h.enrichTimeout)
			defer callCancel()

			resp, err := h.llmBackend.Complete(callCtx, h.buildPrompt(v))
			if err != nil || resp == nil || resp.Text == "" {
				h.metrics.EnrichmentsFailed.Add(1)
				reason := "empty_response"
				if err != nil {
					reason = "error"
					if errors.Is(err, context.DeadlineExceeded) {
						reason = "timeout"
					}
				}
				attrs := []any{"event", "llm_fallback_triggered", "reason", reason, "file", v.FilePath, "import", v.Import}
				if err != nil {
					attrs = append(attrs, logging.ErrorAttrs("llm_complete", err)...)
				}
				h.logger.Warn("llm_fallback_triggered", attrs...)
				return
			}

			structured, parseErr := llm.ParseStructuredExplanation(resp.Text)
			if parseErr != nil {
				h.metrics.EnrichmentsFailed.Add(1)
				attrs := append([]any{"event", "llm_fallback_triggered", "reason", "non_structured_output", "file", v.FilePath, "import", v.Import},
					logging.ErrorAttrs("parse", parseErr)...)
				h.logger.Warn("llm_fallback_triggered", attrs...)
				return
			}

			if err := h.emitEnrichment(baseCtx, requestID, idx, v, structured); err != nil {
				h.metrics.EnrichmentsFailed.Add(1)
				return
			}
			h.metrics.EnrichmentsOK.Add(1)
		}(i, violations[i])
	}
}

// emitEnrichment pushes a single violation's enrichment to the client as a
// JSON-RPC "notifications/message" notification (MCP logging shape).
func (h *CleanArchHandler) emitEnrichment(ctx context.Context, requestID string, idx int, v ArchViolation, s llm.StructuredExplanation) error {
	params := map[string]interface{}{
		"level":  "info",
		"logger": "cleanarch/analyze",
		"data": ViolationEnrichment{
			RequestID:      requestID,
			ViolationIndex: idx,
			FilePath:       v.FilePath,
			Import:         v.Import,
			AIExplanation:  s.AIExplanation,
			SuggestedFix:   s.SuggestedFix,
		},
	}

	if err := h.notifier.Send(ctx, rpc.NewNotification("notifications/message", params)); err != nil {
		attrs := append([]any{"event", "notification_send_failed", "file", v.FilePath, "import", v.Import},
			logging.ErrorAttrs("notify", err)...)
		h.logger.Warn("notification_send_failed", attrs...)
		return err
	}
	return nil
}

// buildPrompt constructs the LLM prompt for a single violation. It includes the
// rule description, the offending package, the prohibited import, and a small
// read-only code snippet around the violating line (best-effort).
func (h *CleanArchHandler) buildPrompt(v ArchViolation) llm.Prompt {
	snippet := readSnippet(v.FilePath, v.LineNumber)

	// Emit key=value lines so the heuristic backend can parse fields, while the
	// Bedrock backend receives the same context as free-form text.
	var b strings.Builder
	fmt.Fprintf(&b, "Rule=%s\n", v.RuleName)
	fmt.Fprintf(&b, "Description=%s\n", v.Description)
	fmt.Fprintf(&b, "FromPkg=%s\n", v.FromPkg)
	fmt.Fprintf(&b, "Import=%s\n", v.Import)
	fmt.Fprintf(&b, "FilePath=%s\n", v.FilePath)
	fmt.Fprintf(&b, "LineNumber=%d\n", v.LineNumber)
	if snippet != "" {
		fmt.Fprintf(&b, "Snippet:\n%s\n", snippet)
	}

	return llm.Prompt{
		System: llm.StructuredExplanationSystemPrompt,
		User:   b.String(),
	}
}

// readSnippet reads a small window of lines around the given 1-based line number.
// This is a read-only operation (os.ReadFile only). On any error it returns "".
func readSnippet(filePath string, lineNumber int) string {
	if filePath == "" || lineNumber <= 0 {
		return ""
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	start := lineNumber - 2
	if start < 0 {
		start = 0
	}
	end := lineNumber + 1
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}

	return strings.Join(lines[start:end], "\n")
}

// RegisterCleanArch registers the cleanarch/analyze tool handler with the RPC dispatcher.
func RegisterCleanArch(d *rpc.Dispatcher, handler *CleanArchHandler) {
	d.Register("cleanarch/analyze", handler.Handle)
}
