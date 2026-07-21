# Implementation Plan: KiroGuard
## Overview

KiroGuard is implemented as a monolithic modular Go binary. The plan builds incrementally: foundation first (types, interfaces, transport), then each module in isolation, followed by wiring and integration. Property-based tests use `pgregory.net/rapid`.

## Tasks

- [x] 1. Project scaffolding and core types
  - [x] 1.1 Initialize Go module and directory structure
    - Run `go mod init github.com/luiferdev/kiroguard`
    - Create all package directories: `cmd/`, `internal/rpc/`, `internal/transport/`, `internal/llm/`, `internal/envguard/`, `internal/vulnscanner/`, `internal/cleanarch/`, `internal/finops/`, `internal/config/`
    - Add `pgregory.net/rapid` and `aws-sdk-go-v2` dependencies to `go.mod`
    - _Requirements: 8.6_
  - [x] 1.2 Implement JSON-RPC 2.0 types and serialization
    - Create `internal/rpc/types.go` with `Request`, `Response`, and `RPCError` structs
    - Create `internal/rpc/errors.go` with standard error codes (-32700, -32600, -32601, -32602, -32603)
    - Implement `ParseRequest(data []byte) (*Request, error)` that validates JSON structure and required fields
    - _Requirements: 1.1, 1.3_
  - [ ]* 1.3 Write property tests for JSON-RPC types
    - **Property 1: JSON-RPC round-trip fidelity**
    - **Property 2: Malformed request produces standard error**
    - **Validates: Requirements 1.1, 1.3, 2.4**
  - [x] 1.4 Implement the Dispatcher with panic recovery
    - Create `internal/rpc/dispatcher.go` with `Dispatcher` struct, `Register()`, and `Dispatch()` methods
    - Implement deferred `recover()` in `dispatchSafe()` that catches panics and returns -32603 errors
    - Implement method routing via `map[string]ToolHandler` with `sync.RWMutex`
    - _Requirements: 1.2, 1.6, 9.1, 9.5_
  - [ ]* 1.5 Write property tests for Dispatcher
    - **Property 3: Concurrent dispatch safety**
    - **Property 16: Panic recovery and server continuity**
    - **Validates: Requirements 1.6, 9.1, 9.5**

- [x] 2. Transport layer
  - [x] 2.1 Define Transport interface and implement Stdio transport
    - Create `internal/transport/transport.go` with `Transport` interface (`Start`, `Send`)
    - Create `internal/transport/stdio.go` reading newline-delimited JSON from stdin, writing to stdout
    - _Requirements: 2.1, 2.4_
  - [x] 2.2 Implement HTTP+SSE transport
    - Create `internal/transport/sse.go` with HTTP server: POST `/message` for requests, GET `/sse` for event stream
    - Implement keep-alive ticker sending comment events every 30 seconds
    - _Requirements: 2.2, 2.5_
  - [ ]* 2.3 Write unit tests for transports
    - Test stdio transport reads/writes correctly with mock reader/writer
    - Test SSE transport starts HTTP server and sends keep-alive events
    - Test invalid transport flag returns error
    - _Requirements: 2.1, 2.2, 2.3_

- [x] 3. Configuration and CLI
  - [x] 3.1 Implement configuration loading and validation
    - Create `internal/config/config.go` with `Config` struct and all nested config types
    - Create `internal/config/defaults.go` with default values
    - Implement `Load(path string) (*Config, error)` with YAML parsing and field-specific validation errors
    - _Requirements: 8.3, 8.4, 8.5_
  - [ ]* 3.2 Write property test for configuration validation
    - **Property 17: Configuration validation error specificity**
    - **Validates: Requirements 8.4**
  - [x] 3.3 Implement CLI entry point
    - Create `main.go` with flag parsing: `--transport` (default "stdio"), `--port` (default 3000), `--config`
    - Validate transport flag value is "stdio" or "sse", exit with error listing supported transports otherwise
    - Wire config loading, transport creation, and dispatcher startup
    - _Requirements: 8.1, 8.2, 2.3_

- [x] 4. Checkpoint - Core foundation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. LLM interface and providers
  - [x] 5.1 Define LLM interface and implement HeuristicProvider
    - Create `internal/llm/interface.go` with `LLMBackend` interface, `Prompt`, and `LLMResponse` types
    - Create `internal/llm/heuristic.go` with template-based provider using `text/template`
    - Register default templates for each module's explanation needs
    - _Requirements: 3.1, 3.5_
  - [x] 5.2 Implement BedrockProvider
    - Create `internal/llm/bedrock.go` using `aws-sdk-go-v2/service/bedrockruntime` to call `InvokeModel`
    - Default model: `anthropic.claude-3-sonnet-20240229-v1:0`, configurable via config
    - Handle credential loading via AWS SDK default chain
    - _Requirements: 3.2_
  - [x] 5.3 Implement LLMRouter with fallback logic
    - Create `internal/llm/router.go` with `LLMRouter` that tries Bedrock first (10s timeout), falls back to heuristic
    - On fallback, set `metadata["fallback"] = "true"` in response
    - _Requirements: 3.3, 3.4, 9.2_
  - [ ]* 5.4 Write property test for LLM fallback
    - **Property 4: LLM fallback metadata invariant**
    - **Validates: Requirements 3.3, 9.2**

- [x] 6. Env-Guard module
  - [x] 6.1 Implement secret pattern scanner
    - Create `internal/envguard/scanner.go` with compiled regex patterns for AWS keys, API tokens, PEM headers, database DSNs, JWTs
    - Implement `Scan(diff string) []SecretFinding` that returns line number, file path, and secret type
    - _Requirements: 4.1, 4.2_
  - [ ]* 6.2 Write property test for secret detection
    - **Property 5: Secret detection completeness**
    - **Validates: Requirements 4.1, 4.2**
  - [x] 6.3 Implement .envguardignore parser
    - Create `internal/envguard/ignore.go` that reads ignore file, compiles glob and regex patterns
    - Implement `Match(line string) bool` method
    - Expose `Filter(findings []SecretFinding) []SecretFinding` to exclude matching findings
    - _Requirements: 4.5, 4.6_
  - [ ]* 6.4 Write property test for ignore file exclusion
    - **Property 6: Ignore file exclusion**
    - **Validates: Requirements 4.5, 4.6**
  - [x] 6.5 Implement secret migrator
    - Create `internal/envguard/migrator.go` using AWS SDK for Secrets Manager and SSM Parameter Store
    - Implement `Migrate(ctx context.Context, secret SecretFinding) (string, error)` returning the ARN
    - Enforce 10-second timeout via context; on failure, return error (caller still blocks commit)
    - _Requirements: 4.3, 4.7_
  - [x] 6.6 Implement Env-Guard handler and replacement logic
    - Create `internal/envguard/handler.go` wiring scanner → ignore filter → migrator → replacement generation
    - Replacement snippet substitutes the literal secret with the reference (e.g., `os.Getenv("SECRET_ARN")`)
    - Register as MCP tool with input schema
    - _Requirements: 4.4, 4.7, 1.4_
  - [ ]* 6.7 Write property test for replacement safety
    - **Property 7: Secret replacement does not contain the original value**
    - **Validates: Requirements 4.4**

- [x] 7. Checkpoint - Env-Guard complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Vuln-Scanner module
  - [x] 8.1 Implement manifest parser for npm and pip
    - Create `internal/vulnscanner/parser.go` with `ParseManifest(content string, ecosystem string) ([]Dependency, error)`
    - Handle `package.json` (JSON parsing, `dependencies` + `devDependencies`) and `requirements.txt` (line-by-line `pkg==version`)
    - _Requirements: 5.1, 5.6_
  - [ ]* 8.2 Write property test for manifest parsing
    - **Property 8: Manifest parsing completeness**
    - **Validates: Requirements 5.1, 5.6**
  - [x] 8.3 Implement OSV.dev client
    - Create `internal/vulnscanner/osv.go` calling `https://api.osv.dev/v1/querybatch`
    - Batch dependencies into requests, deserialize responses into `[]OSVVulnerability`
    - Enforce 30-second total timeout for batch
    - _Requirements: 5.2, 5.7_
  - [x] 8.4 Implement Vuln-Scanner handler
    - Create `internal/vulnscanner/handler.go` wiring parser → OSV client → LLM explanation
    - Map OSV response fields to `VulnFinding` struct with CVE ID, severity, affected range, fixed version
    - On LLM availability, generate human-readable explanation
    - Register as MCP tool
    - _Requirements: 5.3, 5.4, 5.5, 1.4_
  - [ ]* 8.5 Write property test for vulnerability response structure
    - **Property 9: Vulnerability response structure**
    - **Validates: Requirements 5.3**

- [x] 9. Clean-Arch module
  - [x] 9.1 Implement AST-based import graph builder
    - Create `internal/cleanarch/ast.go` using `go/parser` and `go/ast` to parse Go files
    - Build directed graph `map[string][]string` of package → imported packages
    - Walk all `.go` files recursively in given directory
    - _Requirements: 6.1_
  - [ ]* 9.2 Write property test for import graph completeness
    - **Property 10: Import graph completeness**
    - **Validates: Requirements 6.1**
  - [x] 9.3 Implement architecture rules engine
    - Create `internal/cleanarch/rules.go` with YAML rule loading and default rules
    - Implement `Evaluate(graph ImportGraph, rules []Rule) []ArchViolation`
    - Each rule has `from` pattern, `to` pattern, and `allow` flag; patterns support glob-style matching
    - _Requirements: 6.2, 6.5, 6.6_
  - [ ]* 9.4 Write property test for violation detection correctness
    - **Property 11: Architecture violation detection correctness**
    - **Validates: Requirements 6.2, 6.3**
  - [x] 9.5 Implement Clean-Arch handler
    - Create `internal/cleanarch/handler.go` wiring AST analysis → rule evaluation → warning formatting
    - Ensure read-only operation (no file writes)
    - Register as MCP tool
    - _Requirements: 6.3, 6.4, 1.4_
  - [ ]* 9.6 Write property test for source immutability
    - **Property 12: Source code immutability in Clean-Arch**
    - **Validates: Requirements 6.4**

- [x] 10. Checkpoint - Clean-Arch complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. FinOps Guardrail module
  - [x] 11.1 Implement expensive pattern detector
    - Create `internal/finops/detector.go` using `go/ast` to identify: N+1 query loops, unpaginated DynamoDB scans, Lambda without memory, Lambda without timeout
    - Return list of detected patterns with file path, line number, and pattern type
    - _Requirements: 7.1, 7.6_
  - [x] 11.2 Implement cost estimator
    - Create `internal/finops/estimator.go` with formula table keyed by pattern type
    - Input: pattern type, requests per hour (default 1000 if not provided)
    - Apply formulas: `N+1 = queries × rph × 730 × unit_cost`, etc.
    - _Requirements: 7.2, 7.5_
  - [ ]* 11.3 Write property test for cost formula consistency
    - **Property 13: Cost formula consistency**
    - **Validates: Requirements 7.2**
  - [x] 11.4 Implement FinOps handler
    - Create `internal/finops/handler.go` wiring detector → estimator → LLM explanation
    - Format findings with concrete dollar amounts in explanations
    - Register as MCP tool
    - _Requirements: 7.3, 7.4, 7.7, 1.4_
  - [ ]* 11.5 Write property test for finding structure
    - **Property 14: FinOps finding structure completeness**
    - **Validates: Requirements 7.3, 7.6**

- [x] 12. Timeout and resilience
  - [x] 12.1 Implement timeout wrappers for external calls
    - Create helper function `WithTimeout(ctx context.Context, fn func(ctx) error, d time.Duration) error`
    - Apply to all external service calls: OSV.dev, AWS Secrets Manager/SSM, Bedrock
    - Ensure timeout is 10 seconds per call as specified
    - _Requirements: 9.3_
  - [ ]* 12.2 Write property test for timeout enforcement
    - **Property 15: External service timeout enforcement**
    - **Validates: Requirements 9.3**
  - [x] 12.3 Implement structured logging
    - Use `log/slog` with JSON handler in production mode
    - All error paths log with `module`, `error_type`, and stack context fields
    - Add `--log-format` flag for text vs JSON output
    - _Requirements: 9.4_

- [x] 13. MCP protocol integration
  - [x] 13.1 Implement MCP initialize handshake
    - Handle `initialize` method: respond with server info, capabilities, and tool list
    - Handle `tools/list` method: return all 4 registered tools with input schemas
    - _Requirements: 1.4, 1.5_
  - [x] 13.2 Wire all modules into the dispatcher
    - In `main.go`: create config, initialize LLMRouter, create all module handlers, register with dispatcher
    - Start the selected transport with the dispatcher as the message handler
    - Verify the complete request flow: transport → dispatcher → module → response
    - _Requirements: 1.2, 1.4_

- [ ] 14. Final checkpoint - Full integration
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using `pgregory.net/rapid`
- Unit tests validate specific examples and edge cases
- All external service calls are wrapped with 10-second timeouts
- The Go race detector should be enabled during testing (`go test -race`)

## Task Dependency Graph

```json
{
  "waves": [
    {
      "wave": 1,
      "title": "Foundation",
      "tasks": ["1.1", "1.2"],
      "description": "Project scaffolding, Go module init, JSON-RPC types and serialization"
    },
    {
      "wave": 2,
      "title": "Core Infrastructure",
      "tasks": ["1.3", "1.4", "1.5"],
      "depends_on": [1],
      "description": "Property tests for types, Dispatcher with panic recovery, dispatcher tests"
    },
    {
      "wave": 3,
      "title": "Transport & Config",
      "tasks": ["2.1", "2.2", "2.3", "3.1", "3.2", "3.3"],
      "depends_on": [2],
      "description": "Stdio and SSE transports, configuration loading, CLI entry point"
    },
    {
      "wave": 4,
      "title": "Core Checkpoint",
      "tasks": ["4"],
      "depends_on": [3],
      "description": "Verify all foundation tests pass before proceeding to modules"
    },
    {
      "wave": 5,
      "title": "LLM Layer",
      "tasks": ["5.1", "5.2", "5.3", "5.4"],
      "depends_on": [4],
      "description": "LLM interface, HeuristicProvider, BedrockProvider, LLMRouter with fallback"
    },
    {
      "wave": 6,
      "title": "Env-Guard Module",
      "tasks": ["6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7"],
      "depends_on": [5],
      "description": "Secret scanner, .envguardignore parser, AWS migrator, handler and replacement logic"
    },
    {
      "wave": 7,
      "title": "Env-Guard Checkpoint",
      "tasks": ["7"],
      "depends_on": [6],
      "description": "Verify Env-Guard module tests pass"
    },
    {
      "wave": 8,
      "title": "Vuln-Scanner Module",
      "tasks": ["8.1", "8.2", "8.3", "8.4", "8.5"],
      "depends_on": [5, 7],
      "description": "Manifest parser (npm/pip), OSV.dev client, handler with LLM explanations"
    },
    {
      "wave": 9,
      "title": "Clean-Arch Module",
      "tasks": ["9.1", "9.2", "9.3", "9.4", "9.5", "9.6"],
      "depends_on": [5, 8],
      "description": "AST import graph builder, architecture rules engine, read-only handler"
    },
    {
      "wave": 10,
      "title": "Clean-Arch Checkpoint",
      "tasks": ["10"],
      "depends_on": [9],
      "description": "Verify Clean-Arch module tests pass"
    },
    {
      "wave": 11,
      "title": "FinOps Guardrail Module",
      "tasks": ["11.1", "11.2", "11.3", "11.4", "11.5"],
      "depends_on": [5, 10],
      "description": "Expensive pattern detector, cost estimator with formulas, handler with LLM explanations"
    },
    {
      "wave": 12,
      "title": "Resilience & Logging",
      "tasks": ["12.1", "12.2", "12.3"],
      "depends_on": [6, 8, 9, 11],
      "description": "Timeout wrappers for all external calls, structured logging with slog"
    },
    {
      "wave": 13,
      "title": "MCP Protocol Integration",
      "tasks": ["13.1", "13.2"],
      "depends_on": [12],
      "description": "MCP initialize handshake, wire all modules into dispatcher, end-to-end flow"
    },
    {
      "wave": 14,
      "title": "Final Integration Checkpoint",
      "tasks": ["14"],
      "depends_on": [13],
      "description": "Full integration verification, all tests pass with race detector enabled"
    }
  ]
}
```
