**File:** `.kiro/specs/clean-arch/requirements.md`
**Module:** `internal/cleanarch/`
**Tool:** `cleanarch/analyze`

# Requirements: Clean-Arch Module (Background AI Linting)

## Introduction

The Clean-Arch module provides read-only, AST-based architecture linting for Go projects. It scans directory trees to build import dependency graphs, evaluates them against configurable layered-architecture rules, and returns structured warnings. An optional LLM enrichment step generates human-readable explanations for each violation without modifying source code.

## Glossary

- **CleanArch_Analyzer**: The component that parses Go source files and builds import dependency graphs using `go/parser` and `go/ast`
- **Architecture_Rules**: A configurable set of `(from_pattern, to_pattern, allow_boolean)` tuples defining valid and invalid import relationships
- **Arch_Violation**: A structured finding containing the file path, line number, source package, prohibited import, and rule description
- **Import_Edge**: A single import relationship `(file, from_package, import_path, line_number)` extracted from a Go source file
- **LLM_Enricher**: The optional step that sends code snippets and rule context to the `LLMBackend` interface for natural language explanation generation

## Requirements (EARS Format)

### REQ-CA-1: Read-Only Import Graph Construction

- **[Ubiquitous]** THE CleanArch_Analyzer SHALL traverse all `.go` files recursively within the specified directory path, excluding `_test.go` files and `vendor/` directories.
- **[Ubiquitous]** THE CleanArch_Analyzer SHALL parse each file using `go/parser` with `parser.ImportsOnly` mode to extract import declarations.
- **[Ubiquitous]** THE CleanArch_Analyzer SHALL filter out standard library imports by detecting paths whose first segment contains no dot and are not relative imports (`./`, `../`).
- **[Ubiquitous]** THE CleanArch_Analyzer SHALL produce both a deduplicated import graph (`map[string][]string`) and a complete edge list (`[]ImportEdge`) with file path, package path, import path, and source line number for each import statement.
- **[State-Driven]** WHILE walking the directory, IF a file cannot be parsed (syntax error), THEN the analyzer SHALL skip that file silently and continue with the next file.

### REQ-CA-2: Architecture Rule Evaluation

- **[Ubiquitous]** THE RuleEngine SHALL evaluate every Import_Edge against the loaded Architecture_Rules.
- **[Event-Driven]** WHEN an Import_Edge matches a rule with `allow: false`, THE RuleEngine SHALL record an Arch_Violation with the file path, line number, source package, prohibited import path, and the rule's description.
- **[Event-Driven]** WHEN an Import_Edge matches a rule with `allow: true`, THE RuleEngine SHALL immediately skip that edge (allow rules override deny rules for the same edge).
- **[Ubiquitous]** THE RuleEngine SHALL support glob patterns in `from` and `to` fields including `**` (zero or more path segments), `*` (single segment wildcard), and `?` (single character).
- **[Ubiquitous]** THE Module SHALL provide a set of DefaultRules enforcing standard Clean Architecture:
  1. `**/domain/**` SHALL NOT import `**/infrastructure/**`
  2. `**/domain/**` SHALL NOT import `**/presentation/**`
  3. `**/infrastructure/**` SHALL NOT import `**/presentation/**`
- **[Event-Driven]** WHEN the user provides a `rules_file` path in the tool input, THE Module SHALL load rules from that YAML file instead of using defaults.
- **[Unwanted]** IF the rules file cannot be loaded (file not found, invalid YAML), THE Module SHALL return an error and abort the analysis.

### REQ-CA-3: MCP Tool Integration

- **[Ubiquitous]** THE Module SHALL expose an MCP tool named `cleanarch/analyze` accepting parameters: `directory_path` (required, string) and `rules_file` (optional, string).
- **[Ubiquitous]** THE MCP Handler SHALL register with the Dispatcher via `RegisterCleanArch(dispatcher, handler)` following the project's handler pattern.
- **[Event-Driven]** WHEN the tool is invoked, THE Handler SHALL execute the analysis in a background goroutine with a context timeout of 3 seconds.
- **[Unwanted]** IF the scan times out, THE Handler SHALL return partial results — all violations detected before the deadline — with a message indicating the scan was truncated.
- **[Ubiquitous]** The Handler SHALL construct a response containing `violations` (list of Arch_Violation), `total_edges` (integer count), and `message` (summary string).

### REQ-CA-4: Read-Only Guarantee (Hallucination Mitigation)

- **[Ubiquitous]** THE Module SHALL NOT write, modify, or delete any files on disk. All operations are limited to reading `.go` files and returning structured JSON responses.
- **[Ubiquitous]** THE Handler SHALL format all findings as warnings. No suggestion SHALL be automatically applied to source code.
- **[Event-Driven]** WHEN LLM enrichment is enabled and generates a suggested diff, THE Handler SHALL include the suggestion in the response as a text field (`suggested_fix_diff`) and SHALL NOT apply it to any file.

### REQ-CA-5: LLM Enrichment (Optional)

- **[Event-Driven]** WHEN the Handler has access to an `LLMBackend` instance via its constructor, AND violaciones are detected, THE Handler SHALL invoke `LLMBackend.Complete()` for each violation to generate an explanation.
- **[Ubiquitous]** THE LLM prompt SHALL include: the violating file path, the rule description, the prohibited import, and a snippet of the affected code.
- **[Unwanted]** IF the LLM backend is unavailable or returns an error, THE Handler SHALL return the violations without enrichment and continue normally.
- **[Ubiquitous]** THE LLM enrichment SHALL execute concurrently in a separate goroutine. The initial response SHALL NOT be delayed by LLM calls; enrichment data SHALL be attached when available.

## Acceptance Criteria

| ID | Trigger | Expected Result |
|----|---------|-----------------|
| ACA-1 | A package at `internal/domain/service.go` imports `internal/infrastructure/db` | Return 1 violation: file=`domain/service.go`, line=N, import=`internal/infrastructure/db`, rule=`domain → infrastructure`, description=`Domain layer must not import infrastructure` |
| ACA-2 | A package at `internal/presentation/handler.go` imports `internal/domain/model` | Return 0 violations (allowed dependency direction) |
| ACA-3 | A project with no `.go` files or no non-stdlib imports | Return empty violations list, total_edges=0 |
| ACA-4 | `BuildImportGraph` called on a directory with syntax errors in one file | Skip the invalid file, parse all other files, return no error |
| ACA-5 | The handler receives `directory_path=""` | Return an error: `invalid params: directory_path is required` |
| ACA-6 | The handler receives malformed JSON | Return a JSON-RPC error with code -32602 (Invalid Params) |
| ACA-7 | A custom rules file is provided with `allow: true` for a normally denied edge | Return 0 violations for that edge (allow overrides deny) |

### REQ-CA-6: Error Wrapping and Propagation

- **[Ubiquitous]** THE Module SHALL wrap all internal errors using Go's `fmt.Errorf("context: %w", err)` to preserve the original error chain for structured logging and debugging.
- **[Ubiquitous]** THE Module SHALL map internal errors to standard JSON-RPC 2.0 error codes before returning to the client:
  - Parse/validation errors → `-32602` (Invalid Params)
  - File not found / filesystem errors → `-32603` (Internal Error) with descriptive message
  - Rule file load failures → `-32603` with specific field name in message
  - AST parse errors → silently skipped per file (REQ-CA-1), not propagated as RPC errors
- **[Unwanted]** THE Module SHALL NOT use bare `errors.New("message")` for errors that cross the handler boundary — all returned errors MUST use `fmt.Errorf` with `%w` for the root cause.
