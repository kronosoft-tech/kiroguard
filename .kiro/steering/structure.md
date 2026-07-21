# Project Structure

```
kiroguard/
├── main.go                  # Entry point: flag parsing, wiring, transport start
├── cmd/
│   └── root.go              # Reserved for future CLI subcommands (currently empty)
├── internal/                # All internal packages (not importable externally)
│   ├── cleanarch/           # Clean Architecture linting module
│   │   ├── ast.go           # Go AST parsing, import graph construction
│   │   ├── handler.go       # MCP tool handler (cleanarch/analyze)
│   │   └── rules.go         # Rule definition, loading, and evaluation
│   ├── config/              # YAML config loading, validation, defaults
│   ├── envguard/            # Secret detection and migration module
│   │   ├── handler.go       # MCP tool handler (envguard/scan)
│   │   ├── scanner.go       # Regex-based secret pattern detection
│   │   ├── ignore.go        # .envguardignore file parsing
│   │   └── migrator.go      # AWS Secrets Manager / SSM migration
│   ├── finops/              # FinOps cost estimation module
│   │   ├── handler.go       # MCP tool handler (finops/analyze)
│   │   ├── detector.go      # Expensive pattern detection
│   │   └── estimator.go     # Cost calculation logic
│   ├── llm/                 # LLM abstraction layer
│   │   ├── interface.go     # LLMBackend interface definition
│   │   ├── bedrock.go       # AWS Bedrock provider implementation
│   │   ├── heuristic.go     # Regex/template fallback provider
│   │   └── router.go        # Routes to Bedrock with heuristic fallback
│   ├── logging/             # Structured logging utilities
│   ├── rpc/                 # JSON-RPC 2.0 implementation
│   │   ├── types.go         # Request/Response/Error types
│   │   ├── dispatcher.go    # Method routing and handler registry
│   │   ├── errors.go        # Standard JSON-RPC error constructors
│   │   └── mcp.go           # MCP protocol-level handlers (initialize, etc.)
│   ├── timeout/             # Context-based timeout utilities
│   ├── transport/           # MCP transport layer
│   │   ├── transport.go     # Transport interface definition
│   │   ├── stdio.go         # Stdin/stdout line-delimited JSON transport
│   │   └── sse.go           # HTTP + Server-Sent Events transport
│   └── vulnscanner/         # Dependency vulnerability scanning module
│       ├── handler.go       # MCP tool handler
│       ├── parser.go        # Dependency manifest parsers
│       └── osv.go           # OSV API client
└── go.mod / go.sum          # Go module files
```

## Architecture Patterns

- **Module = handler + domain logic**: Each module in `internal/` follows the pattern of a `handler.go` (MCP tool entry point) backed by focused domain files.
- **Dependency injection via constructors**: All handlers receive their dependencies through `New*Handler(...)` constructors. No global state.
- **Dispatcher registration**: Each module exposes a `Register*(dispatcher, handler)` function called from `main.go`.
- **Interface-driven LLM**: The `llm.LLMBackend` interface decouples modules from specific providers. Modules accept the interface, not a concrete type.
- **All packages under `internal/`**: Nothing is exported for external consumption.
- **Tests co-located**: Test files (`*_test.go`) live alongside their source files.
