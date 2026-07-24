# Tech Stack & Build

## Language & Runtime

- **Go 1.26.5**
- Module path: `github.com/luiferdev/kiroguard`

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/aws/aws-sdk-go-v2` | AWS SDK (Bedrock, Secrets Manager, SSM) |
| `gopkg.in/yaml.v3` | YAML config parsing |

No web framework — HTTP/SSE transport is implemented directly with `net/http`.

## Build & Run Commands

```bash
# Build the binary
go build -o kiroguard .

# Run with default settings (stdio transport)
go run .

# Run with SSE transport
go run . -transport sse -port 3000

# Run with a config file
go run . -config path/to/config.yaml

# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for a specific package
go test ./internal/envguard/...

# Tidy dependencies
go mod tidy
```

## CLI Flags

| Flag | Default | Description |
|---|---|---|
| `-transport` | `stdio` | Transport type: `stdio` or `sse` |
| `-port` | `3000` | HTTP port for SSE transport |
| `-config` | `""` | Path to YAML configuration file |
| `-log-format` | `text` | Log output format: `text` or `json` |

## Module Architecture

Each capability lives in its own **flat** package under `internal/<module>/` (no sub-layer folders). Typical files per module:

```
internal/<module>/
  <domain-logic>.go     → parsing/business logic (e.g. parser.go, ast.go, rules.go, scanner.go)
  <external-client>.go  → adapters to external services (e.g. osv.go, migrator.go)
  handler.go            → MCP handler: Input/Output structs, Handle(), RegisterX()
  *_test.go             → hand-written tests, one file per source file
```

Layer boundary rules (validated by the `cleanarch` module itself) still apply **conceptually** — parsing/business logic must not directly call MCP/RPC types — but this is enforced by convention within a single file's responsibilities, not by physical subfolders.

**Enforced layer rules**:
- `**/domain/**` must NOT import `**/infrastructure/**` or `**/presentation/**`
- `**/infrastructure/**` must NOT import `**/presentation/**`

Modules are independent: `internal/cleanarch/` does not import `internal/envguard/`, `internal/vulnscanner/`, or `internal/finops/`, and vice versa. They only share `internal/llm/` (LLMBackend interface) and `internal/rpc/` (dispatcher).

## Agent Scope Rules

- When working on a task scoped to one module (e.g. `internal/cleanarch/`), do NOT modify, refactor, or suggest changes to other modules (`internal/envguard/`, `internal/vulnscanner/`, `internal/finops/`) even if they appear in the directory tree — unless the task explicitly says so.
- Do NOT add new dependencies beyond what's listed in "Key Dependencies" without it being an explicit step in the task file.
- Read-only analysis modules (cleanarch) must never call file-mutation APIs (`os.WriteFile`, `os.Create`, `os.Remove`, etc.) or `exec.Command`. Suggested fixes are returned as text/diff fields only, never applied to disk.

## Conventions

- Standard library `log/slog` for structured logging (no third-party logger).
- Standard library `flag` for CLI argument parsing (no cobra/viper).
- Standard library `testing` for tests (no testify or other test frameworks).
- Mocks for interfaces (e.g. `LLMBackend`) are hand-written structs defined directly in the `_test.go` file — no mocking libraries (gomock, mockery, testify/mock, etc.).
- All errors are wrapped with `fmt.Errorf("context: %w", err)`.
- JSON-RPC 2.0 as the wire protocol — not REST.
