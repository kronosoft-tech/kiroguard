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

## EnvGuard Concurrency

- **Current state**: Zero concurrency — all operations synchronous, no goroutines/channels
- **Independence**: Fully isolated from other modules; changes here never break vulnscanner/cleanarch/finops
- **Scanner**: CPU-bound regex — keep sequential (microseconds per call, parallelization overhead not worth it)
- **Migration**: Sequential 10s timeout per secret — N secrets = N × 10s worst case
- **Recommendation**: Use `errgroup.Group` for concurrent migration (built-in error handling + context cancellation)
- **Rate limiting**: Add `golang.org/x/time/rate` for AWS API calls to avoid throttling
- **Worker count**: Make configurable via `EnvGuardConfig.WorkerCount`
- **Race conditions**: Use index-based updates on findings slice, not append
- **Context cancellation**: Handle graceful cleanup of in-flight migrations
- **Testing**: Mock AWS clients via `NewMigratorWithClients()` — no real AWS calls in tests

## Gotchas

- Bedrock init is non-fatal — falls back to heuristic if AWS credentials are missing
- EnvGuard scans only added lines in diffs (lines starting with `+`), not context/deleted lines
- CleanArch analysis is read-only — never modifies source files
- FinOps heuristic explanations always include dollar amounts
- Stdio transport reads newline-delimited JSON; empty lines are skipped
- `go.mod` says `go 1.26.5` but CI uses Go 1.22 — keep compatibility in mind
