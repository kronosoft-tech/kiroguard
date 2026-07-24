package lambdaguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/luiferdev/kiroguard/internal/logging"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

const (
	defaultSeverityThreshold = "low"
	defaultMaxFileSizeMB     = 5
	defaultScanTimeout       = 15 * time.Second
	defaultMetricsInterval   = 60 * time.Second
)

type Option func(*LambdaGuardHandler)

func WithMetrics(m *Metrics) Option {
	return func(h *LambdaGuardHandler) {
		if m != nil {
			h.metrics = m
		}
	}
}

func WithSeverityThreshold(s string) Option {
	return func(h *LambdaGuardHandler) {
		if s != "" {
			h.severityThreshold = s
		}
	}
}

func WithMaxFileSizeMB(n int) Option {
	return func(h *LambdaGuardHandler) {
		if n > 0 {
			h.maxFileSizeMB = n
		}
	}
}

func WithScanTimeout(d time.Duration) Option {
	return func(h *LambdaGuardHandler) {
		if d > 0 {
			h.scanTimeout = d
		}
	}
}

func WithMetricsInterval(d time.Duration) Option {
	return func(h *LambdaGuardHandler) {
		if d > 0 {
			h.metricsInterval = d
		}
	}
}

type LambdaGuardHandler struct {
	severityThreshold string
	maxFileSizeMB     int
	scanTimeout       time.Duration
	metricsInterval   time.Duration

	baseCtx    context.Context
	baseCancel context.CancelFunc
	inflight   sync.WaitGroup

	metrics *Metrics
	logger  *slog.Logger
}

func NewLambdaGuardHandler(opts ...Option) *LambdaGuardHandler {
	baseCtx, cancel := context.WithCancel(context.Background())
	h := &LambdaGuardHandler{
		severityThreshold: defaultSeverityThreshold,
		maxFileSizeMB:     defaultMaxFileSizeMB,
		scanTimeout:       defaultScanTimeout,
		metricsInterval:   defaultMetricsInterval,
		baseCtx:           baseCtx,
		baseCancel:        cancel,
		metrics:           &Metrics{},
		logger:            logging.ModuleLogger("lambda-guard"),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

func (h *LambdaGuardHandler) MetricsSnapshot() MetricsSnapshot {
	return MetricsSnapshot{
		AnalyzesTotal:    h.metrics.AnalyzesTotal.Load(),
		FunctionsTotal:   h.metrics.FunctionsTotal.Load(),
		FindingsTotal:    h.metrics.FindingsTotal.Load(),
		CriticalFindings: h.metrics.CriticalFindings.Load(),
	}
}

func (h *LambdaGuardHandler) StartMetricsReporter(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = h.metricsInterval
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

func (h *LambdaGuardHandler) reportMetrics() {
	m := h.MetricsSnapshot()
	h.logger.Info("metrics_report",
		"event", "metrics_report",
		"analyzes_total", m.AnalyzesTotal,
		"functions_total", m.FunctionsTotal,
		"findings_total", m.FindingsTotal,
		"critical_findings", m.CriticalFindings)
}

func (h *LambdaGuardHandler) Shutdown(ctx context.Context) error {
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

func (h *LambdaGuardHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var p Params
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

	threshold := h.severityThreshold
	if p.SeverityThreshold != "" {
		threshold = p.SeverityThreshold
	}
	threshold = strings.ToLower(threshold)
	switch threshold {
	case "low", "medium", "high", "critical":
	default:
		return nil, fmt.Errorf("invalid params: %w", rpc.NewValidationError("severity_threshold must be one of: low, medium, high, critical"))
	}

	start := time.Now()
	h.metrics.AnalyzesTotal.Add(1)
	h.logger.Info("scan_started", "event", "scan_started", "target", p.DirectoryPath)

	scanCtx, scanCancel := context.WithTimeout(ctx, h.scanTimeout)
	defer scanCancel()

	configs, err := ParseLambdaConfigs(scanCtx, p.DirectoryPath, h.maxFileSizeMB)
	if err != nil {
		return nil, fmt.Errorf("parse lambda configs: %w", err)
	}

	h.metrics.FunctionsTotal.Add(int64(len(configs)))

	filesScanned := 0
	var allFindings []LambdaFinding
	for i := range configs {
		select {
		case <-scanCtx.Done():
			return nil, fmt.Errorf("scan cancelled: %w", scanCtx.Err())
		default:
		}
		findings := h.analyzeFunction(&configs[i], p.Checks, threshold)
		allFindings = append(allFindings, findings...)
		filesScanned++
	}

	h.metrics.FindingsTotal.Add(int64(len(allFindings)))
	for _, f := range allFindings {
		if f.Severity == "critical" {
			h.metrics.CriticalFindings.Add(1)
		}
	}

	bySeverity := map[string]int{}
	byCategory := map[string]int{}
	for _, f := range allFindings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
	}

	summary := Summary{
		TotalFunctions: len(configs),
		TotalFindings:  len(allFindings),
		BySeverity:     bySeverity,
		ByCategory:     byCategory,
		ScanTimeMs:     time.Since(start).Milliseconds(),
		FilesScanned:   filesScanned,
	}

	h.logger.Info("scan_completed",
		"event", "scan_completed",
		"target", p.DirectoryPath,
		"functions", len(configs),
		"findings", len(allFindings),
		"latency_ms", summary.ScanTimeMs)

	return &Response{
		Functions:  configs,
		Findings:   allFindings,
		Summary:    summary,
		ScanTimeMs: summary.ScanTimeMs,
	}, nil
}

func (h *LambdaGuardHandler) analyzeFunction(cfg *LambdaConfig, checks []string, threshold string) []LambdaFinding {
	var findings []LambdaFinding

	findings = append(findings, AnalyzeIAM(cfg)...)
	findings = append(findings, ScanEnvVars(cfg)...)
	findings = append(findings, ApplyBestPractices(cfg, checks)...)

	return filterByThreshold(findings, threshold)
}

func filterByThreshold(findings []LambdaFinding, threshold string) []LambdaFinding {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	minLevel := severityOrder[threshold]
	var filtered []LambdaFinding
	for _, f := range findings {
		if level, ok := severityOrder[f.Severity]; ok && level >= minLevel {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func RegisterLambdaGuard(d *rpc.Dispatcher, handler *LambdaGuardHandler) {
	d.Register("lambdaguard/analyze", handler.Handle)
}
