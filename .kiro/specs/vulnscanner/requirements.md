**File:** `.kiro/specs/vulnscanner/requirements.md`
**Module:** `internal/vulnscanner/`
**Tool:** `vulnscanner/scan`

# Requirements: Vuln-Scanner Module (Dependency Vulnerability Scanning)

## Introduction

The Vuln-Scanner module analyzes dependency manifests for known security vulnerabilities by querying the public OSV.dev database. It supports npm and pip ecosystems, parses multiple manifest formats (package.json, package-lock.json v1/v2/v3, requirements.txt), and optionally translates technical CVE data into human-readable explanations via the LLMBackend interface.

## Glossary

- **Manifest_Parser**: The component that extracts dependency names and version constraints from package manager files
- **OSV_Client**: The HTTP client that queries `api.osv.dev/v1/querybatch` with a batch of dependency descriptors
- **Vuln_Finding**: A structured result containing CVE/GHSA identifier, severity score, affected version range, fixed version, and optional LLM explanation
- **LLM_Enricher**: The component that sends vulnerability data to the LLMBackend for natural language explanation generation
- **Notifier**: The `rpc.Notifier` interface wired at startup that enables the handler to push asynchronous `notifications/message` JSON-RPC notifications to the connected client (typically only available in SSE transport mode)
- **Ecosystem**: The package manager context — either `"npm"` (Node.js) or `"pip"` (Python)

## Requirements (EARS Format)

### REQ-VS-1: Manifest Parsing

- **[Ubiquitous]** THE Manifest_Parser SHALL accept a manifest content string and an ecosystem identifier (`"npm"` or `"pip"`).
- **[Ubiquitous]** WHEN the ecosystem is `"npm"`, THE Manifest_Parser SHALL parse JSON input and extract dependencies from the following formats:
  1. `package.json` — `dependencies` and `devDependencies` maps (simple string→string)
  2. `package-lock.json` v3 — `packages` map keyed by `node_modules/<name>` paths
  3. `package-lock.json` v1/v2 — legacy top-level `dependencies` map with version objects
- **[Ubiquitous]** WHEN the ecosystem is `"pip"`, THE Manifest_Parser SHALL parse `requirements.txt` format line by line, extracting package name and version for operators `==`, `>=`, `<=`, `!=`, `~=`, and also accepting bare package names without version constraints.
- **[Event-Driven]** WHEN a line in a `requirements.txt` file starts with `#` (comment) or `-` (flag), THE Manifest_Parser SHALL skip that line silently.
- **[Ubiquitous]** THE Manifest_Parser SHALL strip npm semver constraint prefixes (`^`, `~`, `>=`, `<=`, `>`, `<`, `=`, `~>`) from version strings before returning them.
- **[Ubiquitous]** THE Manifest_Parser SHALL reject any manifest string exceeding 5 MB (5,242,880 bytes) with a JSON-RPC error `-32602` (Invalid Params) to prevent memory exhaustion attacks.
- **[Unwanted]** IF the ecosystem is not `"npm"` or `"pip"`, THE Manifest_Parser SHALL return an error with the unsupported ecosystem value.

### REQ-VS-2: OSV.dev Batch Query

- **[Ubiquitous]** THE OSV_Client SHALL build a single HTTP POST request to `https://api.osv.dev/v1/querybatch` containing all extracted dependencies as a batch.
- **[Ubiquitous]** THE OSV_Client SHALL enforce a 30-second total timeout for the batch request using `context.WithTimeout`.
- **[Event-Driven]** WHEN the OSV API returns a successful response (HTTP 200), THE OSV_Client SHALL map each query result back to the corresponding dependency by index position in the response array.
- **[Ubiquitous]** THE OSV_Client SHALL extract from each OSVVulnerability: the vulnerability ID (CVE or GHSA), severity score (CVSS v3 numeric), affected version range (via range events), and fixed version (via the `fixed` event).
- **[Ubiquitous]** THE severity score SHALL be extracted by parsing the CVSS vector string: first attempting direct numeric parsing, then falling back to a heuristic based on high/medium impact indicators in the vector.

### REQ-VS-3: VulnFinding Structure

- **[Ubiquitous]** Every vulnerability returned by the OSV_Client SHALL be mapped to a VulnFinding with the following fields:
  - `cve_id`: the CVE or GHSA identifier (non-empty)
  - `severity_score`: a float in `[0.0, 10.0]` derived from CVSS
  - `affected_range`: human-readable range string (e.g. `">=1.0.0, <2.0.0"`)
  - `fixed_version`: the version where the vulnerability was fixed
  - `package_name`: the name of the affected dependency
  - `explanation`: initially empty, populated by the LLM_Enricher if available

### REQ-VS-4: Error Resilience

- **[Ubiquitous]** THE OSV_Client failures SHALL NOT propagate as JSON-RPC errors. Instead, THE Handler SHALL set the `scan_error` field on the output with the error message and return an empty findings list.
- **[Ubiquitous]** THE Handler SHALL always return a `VulnScannerOutput` struct with `findings`, `total_deps`, and `vuln_count` fields — even when no vulnerabilities are found or when the OSV API fails.
- **[Event-Driven]** WHEN the manifest is empty (no dependencies found), THE Handler SHALL return an empty findings list with `total_deps=0` — not an error.

### REQ-VS-5: LLM Enrichment (Async, Optional)

- **[Event-Driven]** WHEN the Handler has both an `LLMBackend` instance AND an `rpc.Notifier` AND vulnerabilities are detected, THE Handler SHALL return findings **immediately** (without explanations) and enrich AT MOST the top 5 findings by `severity_score` (descending) asynchronously via background goroutines.
- **[Ubiquitous]** THE Handler SHALL sort findings by `severity_score` descending and select the first 5 for LLM enrichment. If there are fewer than 5 findings, all are eligible.
- **[Ubiquitous]** THE Handler SHALL include a `request_id` in the initial response. Each async enrichment notification SHALL carry the same `request_id` for client-side correlation.
- **[Event-Driven]** WHEN an enrichment completes successfully, THE Handler SHALL push a `notifications/message` JSON-RPC notification containing the `FindingEnrichment` payload (request_id, finding_index, package_name, cve_id, ai_explanation) via `notifier.Send()`.
- **[Ubiquitous]** THE LLM prompt SHALL include ONLY: the CVE identifier, package name, severity score, affected range, and fixed version. THE prompt SHALL NOT include raw OSV JSON (affected arrays, database_specific data, etc.).
- **[Ubiquitous]** THE System prompt for the LLM SHALL instruct the model to provide a brief, actionable explanation in under 2 sentences.
- **[Ubiquitous]** THE Handler SHALL enforce a per-LLM-call timeout of 1.5 seconds and a global concurrency limit of 5 simultaneous enrichments across all in-flight requests.
- **[Unwanted]** IF the LLM backend returns an error or times out, THE Handler SHALL silently drop that finding's enrichment notification — the initial response was already delivered.
- **[Unwanted]** IF the `rpc.Notifier` is nil (e.g. no SSE transport), THE Handler SHALL return findings immediately without enrichment — no background goroutines are launched.

### REQ-VS-6: MCP Tool Integration

- **[Ubiquitous]** THE Module SHALL expose an MCP tool named `vulnscanner/scan` accepting parameters: `manifest` (required, string) and `ecosystem` (required, string).
- **[Ubiquitous]** THE Handler SHALL register with the Dispatcher via `RegisterVulnScanner(dispatcher, handler)` following the project's handler pattern.
- **[Ubiquitous]** THE Handler SHALL validate that both `manifest` and `ecosystem` are non-empty before processing, returning a JSON-RPC error `-32602` with a descriptive message if either is missing.

### REQ-VS-7: Error Wrapping and Propagation

- **[Ubiquitous]** THE Module SHALL wrap all internal errors using Go's `fmt.Errorf("context: %w", err)` to preserve the original error chain for structured logging.
- **[Ubiquitous]** THE Module SHALL map validation/parse errors to JSON-RPC `-32602` (Invalid Params) and internal errors (OSV HTTP failures) to the `ScanError` output field — never to an RPC error.

## Acceptance Criteria

| ID | Trigger | Expected Result |
|----|---------|-----------------|
| VCA-1 | `manifest` = `{"dependencies":{"lodash":"^4.17.0"}}`, `ecosystem` = `"npm"` | Return 1 dependency: `lodash@4.17.0` (prefix stripped), ecosystem `npm` |
| VCA-2 | `manifest` = `requests==2.25.0\nflask==2.3.0`, `ecosystem` = `"pip"` | Return 2 dependencies: `requests@2.25.0`, `flask@2.3.0`, both `pypi` |
| VCA-3 | OSV mock returns CVE with severity 9.8 and fix version 4.17.21 | Return 1 finding with `severity_score=9.8`, `fixed_version="4.17.21"` |
| VCA-4 | OSV mock returns HTTP 500 | Return output with `scan_error` populated, `findings` empty, `total_deps` still set |
| VCA-5 | LLM mock returns known explanation text | Return finding with `explanation` populated |
| VCA-6 | LLM mock returns error | Return finding with `explanation=""` (empty), scan not failed |
| VCA-7 | `ecosystem` = `"cargo"` | Return JSON-RPC error `-32602`: `unsupported ecosystem: "cargo"` |
| VCA-8 | Empty manifest `""` | Return JSON-RPC error `-32602`: `manifest is required` |
| VCA-9 | Notifier + LLM available, 7 findings with varying severity | Initial response has `request_id` and empty explanations; exactly 5 enrichment notifications arrive asynchronously |
| VCA-10 | Notifier is nil, LLM available, findings present | Initial response returned immediately, no enrichment notifications fired |
