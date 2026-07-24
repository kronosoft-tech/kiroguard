package iamguard

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

const (
	defaultEnrichTimeout   = 5 * time.Second
	defaultScanTimeout     = 10 * time.Second
	defaultMaxConcurrent   = 3
	defaultMetricsInterval = 60 * time.Second
)

// Metrics holds atomic counters for IAM-Guard, suitable for periodic export
// to CloudWatch / a metrics sink.
type Metrics struct {
	ScansTotal     atomic.Int64
	WildcardsTotal atomic.Int64
	PoliciesOK     atomic.Int64
	PoliciesFailed atomic.Int64
}

// MetricsSnapshot is an immutable point-in-time copy of the counters.
type MetricsSnapshot struct {
	ScansTotal     int64 `json:"scans_total"`
	WildcardsTotal int64 `json:"wildcards_total"`
	PoliciesOK     int64 `json:"policies_ok"`
	PoliciesFailed int64 `json:"policies_failed"`
}

// Option configures an IAMGuardHandler at construction time.
type Option func(*IAMGuardHandler)

// WithEnrichTimeout overrides the per-LLM-call deadline (default 5s).
func WithEnrichTimeout(d time.Duration) Option {
	return func(h *IAMGuardHandler) {
		if d > 0 {
			h.enrichTimeout = d
		}
	}
}

// WithScanTimeout overrides the scan deadline (default 10s).
func WithScanTimeout(d time.Duration) Option {
	return func(h *IAMGuardHandler) {
		if d > 0 {
			h.scanTimeout = d
		}
	}
}

// WithMaxConcurrent overrides the GLOBAL max concurrent LLM calls (default 3).
func WithMaxConcurrent(n int) Option {
	return func(h *IAMGuardHandler) {
		if n > 0 {
			h.maxConcurrent = n
		}
	}
}

// WithMaxFileSize overrides the maximum IaC file size in bytes (default 5MB).
func WithMaxFileSize(size int64) Option {
	return func(h *IAMGuardHandler) {
		if size > 0 {
			h.maxFileSize = size
		}
	}
}

// IAMGuardInput represents the input parameters for the iamguard/analyze tool.
type IAMGuardInput struct {
	DirectoryPath string `json:"directory_path"`
}

// IAMGuardOutput represents the output of the iamguard/analyze tool.
type IAMGuardOutput struct {
	Actions   []AWSAction   `json:"actions"`
	Usages    []SDKUsage    `json:"usages,omitempty"`
	Wildcards []IACWildcard `json:"wildcards,omitempty"`
	Message   string        `json:"message"`
	RequestID string        `json:"request_id,omitempty"`
}

// PolicyEnrichment is the payload delivered asynchronously once the LLM
// generates a least-privilege IAM policy.
type PolicyEnrichment struct {
	RequestID     string `json:"request_id"`
	IAMPolicyJSON string `json:"iam_policy_json"`
	AWSActions    string `json:"aws_actions"`
}

// IAMGuardHandler wires together Go SDK analysis, IaC wildcard scanning, and
// optional async LLM policy generation.
type IAMGuardHandler struct {
	llm      llm.LLMBackend
	notifier rpc.Notifier

	enrichTimeout time.Duration
	scanTimeout   time.Duration
	maxConcurrent int
	maxFileSize   int64

	globalSem chan struct{}

	baseCtx    context.Context
	baseCancel context.CancelFunc
	inflight   sync.WaitGroup

	metrics *Metrics

	logger *slog.Logger
}

// NewIAMGuardHandler creates a new IAMGuardHandler with optional LLM backend
// and configuration Options.
func NewIAMGuardHandler(llmBackend llm.LLMBackend, opts ...Option) *IAMGuardHandler {
	baseCtx, cancel := context.WithCancel(context.Background())
	h := &IAMGuardHandler{
		llm:           llmBackend,
		enrichTimeout: defaultEnrichTimeout,
		scanTimeout:   defaultScanTimeout,
		maxConcurrent: defaultMaxConcurrent,
		baseCtx:       baseCtx,
		baseCancel:    cancel,
		metrics:       &Metrics{},
		logger:        logging.ModuleLogger("iam-guard"),
		maxFileSize:   defaultMaxIACFileSize,
	}
	for _, opt := range opts {
		opt(h)
	}
	h.globalSem = make(chan struct{}, h.maxConcurrent)
	return h
}

// SetNotifier wires the transport used to push async notifications.
func (h *IAMGuardHandler) SetNotifier(n rpc.Notifier) {
	h.notifier = n
}

// MetricsSnapshot returns a point-in-time copy of the operational counters.
func (h *IAMGuardHandler) MetricsSnapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ScansTotal:     h.metrics.ScansTotal.Load(),
		WildcardsTotal: h.metrics.WildcardsTotal.Load(),
		PoliciesOK:     h.metrics.PoliciesOK.Load(),
		PoliciesFailed: h.metrics.PoliciesFailed.Load(),
	}
}

// StartMetricsReporter periodically emits a structured "metrics_report" event
// until ctx is cancelled, then emits one final report. Run it in its own
// goroutine; CloudWatch metric filters can extract the counters from these logs.
func (h *IAMGuardHandler) StartMetricsReporter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultMetricsInterval
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

// reportMetrics logs a single point-in-time metrics snapshot.
func (h *IAMGuardHandler) reportMetrics() {
	m := h.MetricsSnapshot()
	h.logger.Info("metrics_report",
		"event", "metrics_report",
		"scans_total", m.ScansTotal,
		"wildcards_total", m.WildcardsTotal,
		"policies_ok", m.PoliciesOK,
		"policies_failed", m.PoliciesFailed)
}

// Shutdown drains in-flight background policy generation. It waits until all
// goroutines finish or ctx expires; on expiry it cancels them and returns
// ctx.Err().
func (h *IAMGuardHandler) Shutdown(ctx context.Context) error {
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

// waitBackground blocks until all in-flight background work finishes.
func (h *IAMGuardHandler) waitBackground() {
	h.inflight.Wait()
}

// newRequestID returns a short random hex id for correlation.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// Handle processes an iamguard/analyze request.
func (h *IAMGuardHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input IAMGuardInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}

	if input.DirectoryPath == "" {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("directory_path is required"))
	}

	stat, err := os.Stat(input.DirectoryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("directory not found: "+input.DirectoryPath))
		}
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError(err.Error()))
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("path is not a directory: "+input.DirectoryPath))
	}

	start := time.Now()
	h.metrics.ScansTotal.Add(1)
	h.logger.Info("scan_started", "event", "scan_started", "target", input.DirectoryPath)

	actions, usages, err := AnalyzeGoSDKCalls(input.DirectoryPath)
	if err != nil {
		return nil, fmt.Errorf("analyze sdk calls: %w", err)
	}

	wildcards, err := ScanIACForWildcards(input.DirectoryPath, h.maxFileSize)
	if err != nil {
		return nil, fmt.Errorf("scan iac wildcards: %w", err)
	}

	h.metrics.WildcardsTotal.Add(int64(len(wildcards)))
	message := fmt.Sprintf("Found %d IAM actions and %d wildcard statement(s)", len(actions), len(wildcards))

	clientID := rpc.ClientID(ctx)
	enrichmentPossible := h.llm != nil && h.notifier != nil && len(actions) > 0
	enrichmentWillRun := enrichmentPossible && clientID != ""

	var requestID string
	if enrichmentWillRun {
		requestID = newRequestID()
		h.startBackgroundPolicyGen(clientID, requestID, actions, wildcards)
	}

	switch {
	case enrichmentWillRun:
		message += fmt.Sprintf("; AI policy generation will be delivered asynchronously via notifications/message (request_id=%s)", requestID)
	case enrichmentPossible:
		message += "; AI policy generation skipped: open an SSE connection and include its sessionId in the request to receive it"
	}

	h.logger.Info("scan_completed",
		"event", "scan_completed",
		"actions_found", len(actions),
		"wildcards_found", len(wildcards),
		"latency_ms", time.Since(start).Milliseconds())

	return &IAMGuardOutput{
		Actions:   actions,
		Usages:    usages,
		Wildcards: wildcards,
		Message:   message,
		RequestID: requestID,
	}, nil
}

// startBackgroundPolicyGen launches LLM policy generation in a background
// goroutine. The goroutine runs on a detached handler-scoped context and is
// bounded by the global semaphore.
func (h *IAMGuardHandler) startBackgroundPolicyGen(clientID, requestID string, actions []AWSAction, wildcards []IACWildcard) {
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

		callCtx, cancel := context.WithTimeout(baseCtx, h.enrichTimeout)
		defer cancel()

		resp, err := h.llm.Complete(callCtx, buildPrompt(actions, wildcards))
		if err != nil || resp == nil || resp.Text == "" {
			h.metrics.PoliciesFailed.Add(1)
			reason := "empty_response"
			if err != nil {
				reason = "error"
				if errors.Is(err, context.DeadlineExceeded) {
					reason = "timeout"
				}
			}
			attrs := []any{"event", "llm_fallback_triggered", "reason", reason, "request_id", requestID}
			if err != nil {
				attrs = append(attrs, logging.ErrorAttrs("llm_complete", err)...)
			}
			h.logger.Warn("llm_fallback_triggered", attrs...)
			return
		}

		policyJSON, awsActions, parseErr := parsePolicyResponse(resp.Text)
		if parseErr != nil {
			h.metrics.PoliciesFailed.Add(1)
			attrs := append([]any{"event", "llm_fallback_triggered", "reason", "non_structured_output", "request_id", requestID},
				logging.ErrorAttrs("parse", parseErr)...)
			h.logger.Warn("llm_fallback_triggered", attrs...)
			return
		}

		if err := h.emitPolicy(baseCtx, requestID, policyJSON, awsActions); err != nil {
			h.metrics.PoliciesFailed.Add(1)
			return
		}
		h.metrics.PoliciesOK.Add(1)
	}()
}

// emitPolicy pushes the generated policy to the client as a
// notifications/message JSON-RPC notification.
func (h *IAMGuardHandler) emitPolicy(ctx context.Context, requestID, policyJSON, awsActions string) error {
	params := map[string]interface{}{
		"level":  "info",
		"logger": "iamguard/analyze",
		"data": PolicyEnrichment{
			RequestID:     requestID,
			IAMPolicyJSON: policyJSON,
			AWSActions:    awsActions,
		},
	}
	return h.notifier.Send(ctx, rpc.NewNotification("notifications/message", params))
}

// buildPrompt constructs the LLM prompt for IAM policy generation.
func buildPrompt(actions []AWSAction, wildcards []IACWildcard) llm.Prompt {
	system := `You are an AWS IAM policy generator. Respond ONLY with strict JSON: {"iam_policy_json": "...", "aws_actions": "..."}. The iam_policy_json field must contain a valid, minimal IAM policy JSON string with the least privileges needed. Never use Resource '*' unless the action inherently requires it, such as s3:ListAllMyBuckets.`

	var b strings.Builder
	fmt.Fprintln(&b, "Required IAM actions:")
	for _, a := range actions {
		fmt.Fprintf(&b, "- %s (count: %d)\n", a.Action, a.Count)
	}
	if len(wildcards) > 0 {
		fmt.Fprintln(&b, "\nWildcard statements found (review these):")
		for _, w := range wildcards {
			fmt.Fprintf(&b, "- %s at %s:%d\n", w.Statement, w.FilePath, w.LineNumber)
		}
	}

	return llm.Prompt{
		System: system,
		User:   b.String(),
	}
}

// parsePolicyResponse extracts iam_policy_json and aws_actions from the LLM
// structured JSON response.
func parsePolicyResponse(text string) (policyJSON, awsActions string, err error) {
	var result struct {
		IAMPolicyJSON string `json:"iam_policy_json"`
		AWSActions    string `json:"aws_actions"`
	}
	if parseErr := json.Unmarshal([]byte(text), &result); parseErr != nil {
		return "", "", fmt.Errorf("parse policy response: %w", parseErr)
	}
	if result.IAMPolicyJSON == "" {
		return "", "", errors.New("parse policy response: empty iam_policy_json")
	}
	return result.IAMPolicyJSON, result.AWSActions, nil
}

// RegisterIAMGuard registers the iamguard/analyze tool with the RPC dispatcher.
func RegisterIAMGuard(d *rpc.Dispatcher, handler *IAMGuardHandler) {
	d.Register("iamguard/analyze", handler.Handle)
}
