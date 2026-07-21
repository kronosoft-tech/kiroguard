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

## Conventions

- Standard library `log/slog` for structured logging (no third-party logger).
- Standard library `flag` for CLI argument parsing (no cobra/viper).
- Standard library `testing` for tests (no testify or other test frameworks).
- All errors are wrapped with `fmt.Errorf("context: %w", err)`.
- JSON-RPC 2.0 as the wire protocol — not REST.
