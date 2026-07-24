// KiroGuard is an MCP server that acts as a preventive guard before code reaches production.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luiferdev/kiroguard/internal/cleanarch"
	"github.com/luiferdev/kiroguard/internal/config"
	"github.com/luiferdev/kiroguard/internal/envguard"
	"github.com/luiferdev/kiroguard/internal/finops"
	"github.com/luiferdev/kiroguard/internal/iamguard"
	"github.com/luiferdev/kiroguard/internal/lambdaguard"
	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/piiguard"
	"github.com/luiferdev/kiroguard/internal/rpc"
	"github.com/luiferdev/kiroguard/internal/transport"
	"github.com/luiferdev/kiroguard/internal/vulnscanner"
	"golang.org/x/time/rate"
)

func main() {
	// CLI flag definitions.
	transportFlag := flag.String("transport", "stdio", "transport type: stdio or sse")
	portFlag := flag.Int("port", 3000, "HTTP port for SSE transport")
	configFlag := flag.String("config", "", "path to YAML configuration file")
	logFormatFlag := flag.String("log-format", "text", "log output format: text or json")
	flag.Parse()

	// Setup structured logging based on --log-format flag.
	setupLogging(*logFormatFlag)

	// Validate transport flag value.
	if *transportFlag != "stdio" && *transportFlag != "sse" {
		fmt.Fprintf(os.Stderr, "Error: unsupported transport %q. Supported transports: stdio, sse\n", *transportFlag)
		os.Exit(1)
	}

	// Load configuration from file or use defaults.
	cfg, err := config.Load(*configFlag)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Override config with CLI flags if provided.
	cfg.Transport.Type = *transportFlag
	cfg.Transport.Port = *portFlag

	// Setup context with signal handling for graceful shutdown (SIGINT, SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Initialize the LLM layer ---
	// Heuristic provider is always available as fallback.
	heuristic := llm.NewHeuristicProvider()
	var rawBackend llm.LLMBackend = heuristic

	// Try to create the Bedrock provider (non-fatal if it fails).
	bedrockProvider, err := llm.NewBedrockProvider(ctx, cfg.LLM.Region, cfg.LLM.ModelID)
	if err == nil {
		// Circuit Breaker: 3 consecutive AWS Bedrock failures opens circuit for 30s, failing fast in 0ms to heuristic
		cbLLM := llm.NewCircuitBreakerLLM(bedrockProvider, heuristic, 3, 30*time.Second)
		rawBackend = cbLLM
	} else {
		slog.Warn("Bedrock unavailable, using heuristic fallback", "error", err)
	}

	// Wrap with thread-safe O(1) LRU Cache (capacity: 1000 prompts) to prevent duplicate token costs and API latency.
	cachedLLM := llm.NewCachedLLM(rawBackend, 1000)
	var llmBackend llm.LLMBackend = cachedLLM

	// --- Create the dispatcher and register MCP protocol handlers ---
	dispatcher := rpc.NewDispatcher()
	rpc.RegisterMCPHandlers(dispatcher)

	// --- Register module handlers ---

	// Env-Guard: secrets detection and migration.
	scanner := envguard.NewSecretScanner()
	var ignoreParser *envguard.IgnoreParser
	if _, statErr := os.Stat(cfg.EnvGuard.IgnoreFile); statErr == nil {
		ignoreParser, _ = envguard.LoadIgnoreFile(cfg.EnvGuard.IgnoreFile)
	}
	limiter := rate.NewLimiter(rate.Limit(cfg.EnvGuard.RateLimit), cfg.EnvGuard.RateBurst)
	envHandler := envguard.NewEnvGuardHandler(scanner, ignoreParser, nil, cfg.EnvGuard.WorkerCount, limiter)
	envguard.RegisterEnvGuard(dispatcher, envHandler)

	// Exporta metricas de Env-Guard como logs estructurados (CloudWatch-native).
	go envHandler.StartMetricsReporter(ctx, time.Duration(cfg.EnvGuard.MetricsIntervalMs)*time.Millisecond)

	// Vuln-Scanner: dependency vulnerability scanning.
	osvClient := vulnscanner.NewOSVClient()
	vulnHandler := vulnscanner.NewVulnScannerHandler(osvClient, llmBackend,
		vulnscanner.WithEnrichTimeout(time.Duration(cfg.VulnScanner.EnrichTimeoutMs)*time.Millisecond),
		vulnscanner.WithMaxConcurrent(cfg.VulnScanner.MaxConcurrent),
		vulnscanner.WithMaxPerRequest(cfg.VulnScanner.MaxPerRequest),
	)
	vulnscanner.RegisterVulnScanner(dispatcher, vulnHandler)

	// Periodically export Vuln-Scanner metrics as structured logs (CloudWatch-native).
	go vulnHandler.StartMetricsReporter(ctx, time.Duration(cfg.VulnScanner.MetricsIntervalMs)*time.Millisecond)

	// Clean-Arch: AI-powered architecture linting.
	var defaultRules []cleanarch.Rule
	if _, statErr := os.Stat(cfg.CleanArch.RulesFile); statErr == nil {
		rules, loadErr := cleanarch.LoadRules(cfg.CleanArch.RulesFile)
		if loadErr == nil {
			defaultRules = rules
		}
	}
	archHandler := cleanarch.NewCleanArchHandler(defaultRules, llmBackend,
		cleanarch.WithScanTimeout(time.Duration(cfg.CleanArch.TimeoutMs)*time.Millisecond),
		cleanarch.WithEnrichTimeout(time.Duration(cfg.CleanArch.EnrichTimeoutMs)*time.Millisecond),
		cleanarch.WithMaxConcurrent(cfg.CleanArch.MaxConcurrent),
		cleanarch.WithMaxEnrichmentsPerRequest(cfg.CleanArch.MaxEnrichmentsPerRequest),
	)
	cleanarch.RegisterCleanArch(dispatcher, archHandler)

	// Periodically export Clean-Arch metrics as structured logs (CloudWatch-native).
	go archHandler.StartMetricsReporter(ctx, time.Duration(cfg.CleanArch.MetricsIntervalMs)*time.Millisecond)

	// FinOps Guardrail: pre-deploy cost estimation.
	detector := finops.NewPatternDetector()
	estimator := finops.NewCostEstimator(cfg.FinOps.DefaultRPH)
	finopsHandler := finops.NewFinOpsHandler(detector, estimator, llmBackend)
	finops.RegisterFinOps(dispatcher, finopsHandler)

	// IAM-Guard: least-privilege IAM policy enforcement.
	iamHandler := iamguard.NewIAMGuardHandler(llmBackend,
		iamguard.WithEnrichTimeout(time.Duration(cfg.IAMGuard.EnrichTimeoutMs)*time.Millisecond),
		iamguard.WithScanTimeout(time.Duration(cfg.IAMGuard.ScanTimeoutMs)*time.Millisecond),
		iamguard.WithMaxConcurrent(cfg.IAMGuard.MaxConcurrent),
		iamguard.WithMaxFileSize(int64(cfg.IAMGuard.MaxFileSizeMb)*1024*1024),
	)
	iamguard.RegisterIAMGuard(dispatcher, iamHandler)

	// Periodically export IAM-Guard metrics as structured logs (CloudWatch-native).
	go iamHandler.StartMetricsReporter(ctx, time.Duration(cfg.IAMGuard.MetricsIntervalMs)*time.Millisecond)

	// LambdaGuard: serverless security analysis.
	lambdaHandler := lambdaguard.NewLambdaGuardHandler(
		lambdaguard.WithSeverityThreshold(cfg.LambdaGuard.SeverityThreshold),
		lambdaguard.WithMaxFileSizeMB(cfg.LambdaGuard.MaxFileSizeMb),
		lambdaguard.WithScanTimeout(time.Duration(cfg.LambdaGuard.ScanTimeoutMs)*time.Millisecond),
	)
	lambdaguard.RegisterLambdaGuard(dispatcher, lambdaHandler)

	// Periodically export LambdaGuard metrics as structured logs (CloudWatch-native).
	go lambdaHandler.StartMetricsReporter(ctx, time.Duration(cfg.LambdaGuard.MetricsIntervalMs)*time.Millisecond)

	// PII-Guard: privacy and compliance scanning.
	piiHandler := piiguard.NewPIIGuardHandler(
		piiguard.WithLLM(llmBackend),
		piiguard.WithSeverityThreshold(cfg.PIIGuard.SeverityThreshold),
		piiguard.WithMaxFileSizeMB(cfg.PIIGuard.MaxFileSizeMb),
		piiguard.WithEntropyThreshold(cfg.PIIGuard.EntropyThreshold),
		piiguard.WithScanTimeout(time.Duration(cfg.PIIGuard.ScanTimeoutMs)*time.Millisecond),
		piiguard.WithEnrichTimeout(time.Duration(cfg.PIIGuard.EnrichTimeoutMs)*time.Millisecond),
		piiguard.WithMaxConcurrent(cfg.PIIGuard.MaxConcurrent),
	)
	piiguard.RegisterPIIGuard(dispatcher, piiHandler)

	// Periodically export PII-Guard metrics as structured logs (CloudWatch-native).
	go piiHandler.StartMetricsReporter(ctx, time.Duration(cfg.PIIGuard.MetricsIntervalMs)*time.Millisecond)

	// --- Create the transport ---
	var t transport.Transport
	var sseT *transport.SSETransport // non-nil only in SSE mode
	switch cfg.Transport.Type {
	case "stdio":
		t = transport.NewStdioTransport(os.Stdin, os.Stdout)
	case "sse":
		addr := fmt.Sprintf(":%d", cfg.Transport.Port)
		sseT = transport.NewSSETransport(addr)
		authTokens := cfg.Transport.AuthTokens
		if cfg.Transport.AuthToken != "" {
			authTokens = append(authTokens, cfg.Transport.AuthToken)
		}
		sseT.SetAuthTokens(authTokens)
		if len(authTokens) == 0 {
			slog.Warn("SSE transport running WITHOUT authentication; set transport.auth_token(s) or place it behind an authenticated gateway")
		}

		// Register all module-level metrics providers for the /metrics endpoint.
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"envguard": envHandler.MetricsSnapshot()}
		})
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"vulnscanner": vulnHandler.MetricsSnapshot()}
		})
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"cleanarch": archHandler.MetricsSnapshot()}
		})
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"iamguard": iamHandler.MetricsSnapshot()}
		})
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"lambdaguard": lambdaHandler.MetricsSnapshot()}
		})
		sseT.RegisterMetricsSnapshotter(func() map[string]interface{} {
			return map[string]interface{}{"piiguard": piiHandler.MetricsSnapshot()}
		})

		sseT.SetReady(true)
		t = sseT
	}

	// Wire the transport as the notifier for modules that push asynchronous LLM
	// enrichment to the client via JSON-RPC notifications.
	archHandler.SetNotifier(t)
	vulnHandler.SetNotifier(t)
	iamHandler.SetNotifier(t)
	piiHandler.SetNotifier(t)

	// Create a MessageHandler that wraps the dispatcher's Dispatch method.
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		return dispatcher.Dispatch(ctx, req), nil
	}

	slog.Info("starting KiroGuard", "transport", cfg.Transport.Type, "port", cfg.Transport.Port)

	// Start the transport (blocks until context is cancelled or error).
	startErr := t.Start(ctx, handler)

	// Drain in-flight Clean-Arch background enrichment before exiting so async
	// LLM work isn't cut off mid-flight on shutdown.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer drainCancel()
	if derr := archHandler.Shutdown(drainCtx); derr != nil {
		slog.Warn("clean-arch enrichment drain incomplete", "error", derr)
	}

	// Drain in-flight Vuln-Scanner enrichment goroutines as well.
	vulnHandler.Shutdown()

	// Drain in-flight IAM-Guard background policy generation.
	if derr := iamHandler.Shutdown(drainCtx); derr != nil {
		slog.Warn("iam-guard policy generation drain incomplete", "error", derr)
	}

	// Drain in-flight LambdaGuard scans before exiting.
	if derr := lambdaHandler.Shutdown(drainCtx); derr != nil {
		slog.Warn("lambda-guard scan drain incomplete", "error", derr)
	}

	// Drain in-flight PII-Guard LLM verification goroutines.
	if derr := piiHandler.Shutdown(drainCtx); derr != nil {
		slog.Warn("pii-guard verification drain incomplete", "error", derr)
	}

	if startErr != nil && ctx.Err() == nil {
		slog.Error("transport error", "error", startErr)
		os.Exit(1)
	}
	slog.Info("shutting down gracefully")
}

// setupLogging configures the global slog logger based on the format flag.
func setupLogging(format string) {
	var handler slog.Handler

	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	default:
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	}

	slog.SetDefault(slog.New(handler))
}
