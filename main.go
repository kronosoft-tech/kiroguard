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

	"github.com/luiferdev/kiroguard/internal/cleanarch"
	"github.com/luiferdev/kiroguard/internal/config"
	"github.com/luiferdev/kiroguard/internal/envguard"
	"github.com/luiferdev/kiroguard/internal/finops"
	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
	"github.com/luiferdev/kiroguard/internal/transport"
	"github.com/luiferdev/kiroguard/internal/vulnscanner"
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
	var llmBackend llm.LLMBackend = heuristic

	// Try to create the Bedrock provider (non-fatal if it fails).
	bedrockProvider, err := llm.NewBedrockProvider(ctx, cfg.LLM.Region, cfg.LLM.ModelID)
	if err == nil {
		llmBackend = llm.NewLLMRouter(bedrockProvider, heuristic)
	} else {
		slog.Warn("Bedrock unavailable, using heuristic fallback", "error", err)
	}

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
	envHandler := envguard.NewEnvGuardHandler(scanner, ignoreParser, nil)
	envguard.RegisterEnvGuard(dispatcher, envHandler)

	// Vuln-Scanner: dependency vulnerability scanning.
	osvClient := vulnscanner.NewOSVClient()
	vulnHandler := vulnscanner.NewVulnScannerHandler(osvClient, llmBackend)
	vulnscanner.RegisterVulnScanner(dispatcher, vulnHandler)

	// Clean-Arch: AI-powered architecture linting.
	var defaultRules []cleanarch.Rule
	if _, statErr := os.Stat(cfg.CleanArch.RulesFile); statErr == nil {
		rules, loadErr := cleanarch.LoadRules(cfg.CleanArch.RulesFile)
		if loadErr == nil {
			defaultRules = rules
		}
	}
	archHandler := cleanarch.NewCleanArchHandler(defaultRules)
	cleanarch.RegisterCleanArch(dispatcher, archHandler)

	// FinOps Guardrail: pre-deploy cost estimation.
	detector := finops.NewPatternDetector()
	estimator := finops.NewCostEstimator(cfg.FinOps.DefaultRPH)
	finopsHandler := finops.NewFinOpsHandler(detector, estimator, llmBackend)
	finops.RegisterFinOps(dispatcher, finopsHandler)

	// --- Create the transport ---
	var t transport.Transport
	switch cfg.Transport.Type {
	case "stdio":
		t = transport.NewStdioTransport(os.Stdin, os.Stdout)
	case "sse":
		addr := fmt.Sprintf(":%d", cfg.Transport.Port)
		t = transport.NewSSETransport(addr)
	}

	// Create a MessageHandler that wraps the dispatcher's Dispatch method.
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		return dispatcher.Dispatch(ctx, req), nil
	}

	slog.Info("starting KiroGuard", "transport", cfg.Transport.Type, "port", cfg.Transport.Port)

	// Start the transport (blocks until context is cancelled or error).
	if err := t.Start(ctx, handler); err != nil {
		if ctx.Err() != nil {
			// Graceful shutdown triggered by signal.
			slog.Info("shutting down gracefully")
			return
		}
		slog.Error("transport error", "error", err)
		os.Exit(1)
	}
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
