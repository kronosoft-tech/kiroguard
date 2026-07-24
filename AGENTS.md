# KiroGuard

MCP (Model Context Protocol) server for code quality and security analysis. Go 1.26.5, single binary, JSON-RPC 2.0.

## Quick Commands

```bash
go build -o kiroguard .          # Build binary
go test ./...                    # Run all tests
go test -race ./...              # Tests with race detector
go test -run TestName ./pkg/...  # Run specific test in a package
go run .                        # Start in stdio mode (default)
go run . -transport sse -port 8080  # Start in SSE mode
go mod tidy                      # Clean dependencies
```

## Architecture

- **Entry**: `main.go` parses flags, loads config, wires modules, starts transport
- **Modules**: Each lives in `internal/<name>/` with `handler.go`, types, and tests
- **Dispatcher**: `internal/rpc/dispatcher.go` routes JSON-RPC methods to handlers
- **Transport**: `internal/transport/` — `stdio` or `sse` (HTTP + Server-Sent Events)
- **LLM**: `internal/llm/` — Bedrock provider + heuristic fallback, routed via `LLMRouter`

### Module Registration Pattern

Every module exposes `Register*(dispatcher, handler)` that calls `dispatcher.Register("tool/name", ...)`. Tool names: `envguard/scan`, `vulnscanner/scan`, `cleanarch/analyze`, `finops/analyze`.

### Handler Contract

Handlers receive `context.Context` + `json.RawMessage` params, return `(interface{}, error)`. The dispatcher wraps errors into `*rpc.RPCError` with standard JSON-RPC error codes.

## Testing

- Tests are co-located with source (`*_test.go`), same package
- Use `httptest.NewServer` for HTTP mocking (see `vulnscanner/handler_test.go`)
- Use `t.TempDir()` + `os.WriteFile` for filesystem fixtures
- Use table-driven tests with `t.Run` for parameterized cases
- Compile-time interface checks: `var _ Interface = (*Impl)(nil)`
- LLM mocks implement `llm.LLMBackend` with configurable responses/errors

## CI

GitHub Actions (`.github/workflows/test.yml`): conflict check → `go build ./...` → `go test -v -race -coverprofile=coverage.out ./...`. Runs on PRs to `develop` and all pushes.

## Config

`config.yaml` (optional) merges with defaults. Key fields: `transport.type`, `transport.port`, `llm.region`, `llm.model_id`, `envguard.ignore_file`, `cleanarch.rules_file`, `finops.default_requests_per_hour`.

## EnvGuard (Concurrency & Production Hardening)

Implemented state (production-ready, on par with Clean-Arch):

- **Scanner**: CPU-bound regex, kept sequential (parallelization overhead not worth it).
- **Concurrent migration**: bounded worker pool via `errgroup.Group` + `SetLimit(WorkerCount)`; results written by index on the findings slice (no race).
- **Rate limiting**: shared `golang.org/x/time/rate` limiter for AWS calls (`RateLimit`/`RateBurst`); each migration also has a 10s timeout.
- **Config knobs**: `EnvGuardConfig.WorkerCount`, `RateLimit`, `RateBurst`, `MetricsIntervalMs` (validated in `config.validate`).
- **Error contract**: malformed params return JSON-RPC `-32602` via `rpc.NewValidationError`.
- **Observability**: structured events (`scan_started`, `scan_completed`, `migration_succeeded`, `migration_failed`) tagged `module=env-guard`. Secret values are NEVER logged (redaction) — only type, path, line, ARN, or error reason.
- **Metrics**: atomic counters (`MetricsSnapshot()`) exported periodically as `metrics_report` logs via `StartMetricsReporter` (CloudWatch-native).
- **Independence**: fully isolated from other modules; changes here never break vulnscanner/cleanarch/finops.
- **Testing**: mock AWS clients via `NewMigratorWithClients()`; inject a buffer-backed `slog` logger to assert events and redaction — no real AWS calls in tests.

## Gotchas

- Bedrock init is non-fatal — falls back to heuristic if AWS credentials are missing
- EnvGuard scans only added lines in diffs (lines starting with `+`), not context/deleted lines
- CleanArch analysis is read-only — never modifies source files
- FinOps heuristic explanations always include dollar amounts
- Stdio transport reads newline-delimited JSON; empty lines are skipped
- `go.mod` requires `go 1.26.5`; CI (`.github/workflows/test.yml`) is pinned to the matching `1.26.5` toolchain
