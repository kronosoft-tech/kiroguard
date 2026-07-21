# Requirements Document

## Introduction

KiroGuard is an MCP (Model Context Protocol) server that acts as a preventive guard before code reaches production. It provides four security and quality modules: Env-Guard (secrets detection and migration), Vuln-Scanner (dependency vulnerability scanning), Clean-Arch (AI-powered architecture linting), and FinOps Guardrail (pre-deploy cost estimation). The server is built in Go as a single binary with dual transport support (stdio and HTTP+SSE), communicates via JSON-RPC 2.0, and uses a pluggable LLM interface with AWS Bedrock as the primary backend.

## Glossary

- **MCP_Server**: The KiroGuard Model Context Protocol server application that exposes tools to MCP clients via JSON-RPC 2.0
- **Env_Guard**: The secrets detection and migration module that scans diffs for leaked secrets
- **Vuln_Scanner**: The dependency vulnerability scanning module that queries OSV.dev for known exploits
- **Clean_Arch**: The AI-powered architecture linting module that analyzes directory trees using AST parsing
- **FinOps_Guardrail**: The pre-deploy cost estimation module that detects expensive code patterns
- **LLM_Interface**: The pluggable interface for large language model backends used for natural language explanations
- **Transport_Layer**: The communication layer supporting both stdio and HTTP+SSE protocols
- **JSON_RPC_Handler**: The component responsible for parsing and routing JSON-RPC 2.0 messages
- **OSV_Client**: The client that queries the OSV.dev vulnerability database
- **AST_Analyzer**: The component that parses source code into abstract syntax trees for analysis
- **Envguardignore_Parser**: The component that parses `.envguardignore` files for false positive mitigation
- **Cost_Estimator**: The component that calculates estimated monthly costs based on AWS public pricing and execution frequency
- **Secret_Migrator**: The component that migrates detected secrets to AWS Secrets Manager or SSM Parameter Store
- **Architecture_Rules**: The configurable rule set defining valid layer dependencies in a project

## Requirements

### Requirement 1: MCP Server Core

**User Story:** As a developer, I want KiroGuard to be a compliant MCP server, so that it integrates seamlessly with MCP-compatible clients and editors.

#### Acceptance Criteria

1. THE MCP_Server SHALL implement the JSON-RPC 2.0 protocol as specified by the MCP standard
2. WHEN the MCP_Server receives a valid JSON-RPC 2.0 request, THE JSON_RPC_Handler SHALL parse the request and route it to the appropriate module handler
3. WHEN the MCP_Server receives a malformed JSON-RPC 2.0 request, THE JSON_RPC_Handler SHALL return a standard JSON-RPC 2.0 error response with error code -32700 (Parse error) or -32600 (Invalid Request)
4. THE MCP_Server SHALL expose each module as a separate MCP tool with its own input schema and description
5. WHEN a client sends an `initialize` request, THE MCP_Server SHALL respond with server capabilities including the list of available tools
6. THE MCP_Server SHALL process multiple concurrent tool invocations using goroutines without data races

### Requirement 2: Dual Transport

**User Story:** As a developer, I want to connect to KiroGuard via either stdio or HTTP+SSE, so that I can use it in different environments (local editor or remote service).

#### Acceptance Criteria

1. WHEN the MCP_Server starts with the `--transport=stdio` flag, THE Transport_Layer SHALL communicate via standard input and standard output
2. WHEN the MCP_Server starts with the `--transport=sse` flag, THE Transport_Layer SHALL start an HTTP server with Server-Sent Events for server-to-client messages and accept POST requests for client-to-server messages
3. IF an unsupported transport flag value is provided, THEN THE MCP_Server SHALL exit with an error message listing supported transports
4. THE Transport_Layer SHALL serialize all responses as valid JSON-RPC 2.0 messages regardless of the selected transport
5. WHEN using SSE transport, THE Transport_Layer SHALL maintain persistent connections and send keep-alive events every 30 seconds to prevent connection timeouts

### Requirement 3: LLM Interface

**User Story:** As a developer, I want KiroGuard to use a pluggable LLM backend, so that it can provide human-readable explanations and the backend can be swapped without changing module logic.

#### Acceptance Criteria

1. THE LLM_Interface SHALL define a Go interface with methods for text generation that modules consume
2. WHEN Bedrock credentials are available and the service is reachable, THE LLM_Interface SHALL route requests to AWS Bedrock
3. IF the Bedrock backend is unreachable or returns an error, THEN THE LLM_Interface SHALL fall back to the heuristic backend and include a warning in the response metadata
4. THE LLM_Interface SHALL accept a prompt string and return a structured response containing the generated text and metadata
5. WHEN falling back to heuristic mode, THE LLM_Interface SHALL produce responses using template-based logic without external network calls

### Requirement 4: Env-Guard (Secrets Module)

**User Story:** As a developer, I want KiroGuard to detect secrets in my code diffs and automatically migrate them to secure storage, so that secrets never reach version control.

#### Acceptance Criteria

1. WHEN the Env_Guard tool receives a diff string, THE Env_Guard SHALL scan it for known secret patterns including AWS keys, API tokens, database connection strings, and private keys
2. WHEN a secret is detected in the diff, THE Env_Guard SHALL block the commit and return the line number, file path, and secret type in the response
3. WHEN a secret is detected, THE Secret_Migrator SHALL store the secret value in AWS Secrets Manager or SSM Parameter Store and return the reference ARN
4. WHEN a secret is migrated, THE Env_Guard SHALL provide a replacement snippet that substitutes the literal secret with the secure reference
5. WHEN a detected pattern matches an entry in the `.envguardignore` file, THE Envguardignore_Parser SHALL exclude that pattern from the results
6. THE Envguardignore_Parser SHALL support glob patterns and regex patterns for defining exclusions
7. IF the Secret_Migrator cannot connect to AWS, THEN THE Env_Guard SHALL still block the commit and report the detected secret with a warning that automatic migration failed

### Requirement 5: Vuln-Scanner (Dependencies Module)

**User Story:** As a developer, I want KiroGuard to scan my dependencies for known vulnerabilities before and after install, so that I avoid introducing exploitable packages.

#### Acceptance Criteria

1. WHEN the Vuln_Scanner tool receives a package manifest (package.json or requirements.txt), THE Vuln_Scanner SHALL extract all direct dependencies with their versions
2. WHEN dependencies are extracted, THE OSV_Client SHALL query the OSV.dev API for each dependency to retrieve known vulnerabilities
3. WHEN vulnerabilities are found, THE Vuln_Scanner SHALL return for each vulnerability: the CVE identifier, severity score, affected version range, and fixed version
4. WHEN vulnerabilities are found and the LLM_Interface is available, THE Vuln_Scanner SHALL include a human-readable explanation of the vulnerability impact generated by the LLM_Interface
5. IF the OSV.dev API is unreachable, THEN THE Vuln_Scanner SHALL return an error response indicating the scan could not be completed
6. THE Vuln_Scanner SHALL support both npm (package.json, package-lock.json) and pip (requirements.txt, Pipfile.lock) ecosystems
7. WHEN scanning a manifest, THE Vuln_Scanner SHALL complete the scan within 30 seconds for manifests containing up to 200 dependencies

### Requirement 6: Clean-Arch (AI Linting Module)

**User Story:** As a developer, I want KiroGuard to analyze my project structure and detect architecture violations, so that I maintain clean layer boundaries.

#### Acceptance Criteria

1. WHEN the Clean_Arch tool receives a directory path, THE AST_Analyzer SHALL parse all Go source files and build an import dependency graph
2. WHEN the dependency graph is built, THE Clean_Arch SHALL evaluate imports against the configured Architecture_Rules to identify layer violations
3. WHEN a layer violation is detected, THE Clean_Arch SHALL return a warning containing the violating file path, line number, the import that violates the rule, and the rule description
4. THE Clean_Arch SHALL operate in non-blocking mode, returning results as warnings only and never modifying source code
5. WHEN no Architecture_Rules configuration file exists, THE Clean_Arch SHALL use default rules based on standard layered architecture (domain cannot import infrastructure, infrastructure cannot import presentation)
6. THE Architecture_Rules SHALL be configurable via a YAML file specifying allowed and forbidden import relationships between packages

### Requirement 7: FinOps Guardrail (Cost Module)

**User Story:** As a developer, I want KiroGuard to estimate the cost impact of my code before deployment, so that I can avoid unexpectedly expensive patterns.

#### Acceptance Criteria

1. WHEN the FinOps_Guardrail tool receives source code, THE FinOps_Guardrail SHALL scan for known expensive patterns including N+1 query loops, unpaginated Lambda invocations, and functions without timeout or memory tuning
2. WHEN an expensive pattern is detected, THE Cost_Estimator SHALL calculate an estimated monthly cost using AWS public pricing multiplied by the estimated execution frequency provided in the request context
3. WHEN cost estimation is complete, THE FinOps_Guardrail SHALL return for each finding: the pattern type, file path, line number, estimated monthly cost, and a human-readable explanation
4. WHEN the LLM_Interface is available, THE FinOps_Guardrail SHALL use it to generate the human-readable cost explanation with concrete dollar amounts
5. IF no execution frequency context is provided, THEN THE Cost_Estimator SHALL use a default baseline of 1000 requests per hour for estimation
6. THE FinOps_Guardrail SHALL detect at minimum: N+1 query loops, unpaginated DynamoDB scans, Lambda functions without memory configuration, and Lambda functions without timeout configuration
7. WHEN falling back to heuristic mode, THE Cost_Estimator SHALL produce cost estimates using static formulas based on AWS public pricing without LLM involvement

### Requirement 8: Configuration and CLI

**User Story:** As a developer, I want to configure KiroGuard via CLI flags and configuration files, so that I can customize its behavior for my project.

#### Acceptance Criteria

1. THE MCP_Server SHALL accept a `--transport` flag with values `stdio` or `sse` to select the communication transport
2. THE MCP_Server SHALL accept a `--port` flag to configure the HTTP listening port when using SSE transport, defaulting to 3000
3. THE MCP_Server SHALL accept a `--config` flag pointing to a YAML configuration file for module-specific settings
4. WHEN a configuration file is provided, THE MCP_Server SHALL validate the file structure and report specific errors for invalid fields
5. IF no configuration file is provided, THEN THE MCP_Server SHALL use sensible defaults for all modules
6. THE MCP_Server SHALL compile into a single statically-linked binary for deployment

### Requirement 9: Error Handling and Resilience

**User Story:** As a developer, I want KiroGuard to handle errors gracefully and continue operating even when individual modules fail, so that partial functionality is always available.

#### Acceptance Criteria

1. WHEN a module encounters an unrecoverable error during tool execution, THE MCP_Server SHALL return a JSON-RPC 2.0 error response with a descriptive message and continue serving other requests
2. WHEN the LLM_Interface fallback is triggered, THE MCP_Server SHALL include a `"fallback": true` field in the response metadata
3. WHEN an external service (OSV.dev, AWS Secrets Manager, Bedrock) times out, THE MCP_Server SHALL enforce a maximum timeout of 10 seconds per external call and return a timeout error
4. THE MCP_Server SHALL log all errors with structured logging including timestamp, module name, error type, and stack context
5. IF a module panics, THEN THE MCP_Server SHALL recover the panic, log the incident, and return a JSON-RPC 2.0 internal error response without crashing the server process
