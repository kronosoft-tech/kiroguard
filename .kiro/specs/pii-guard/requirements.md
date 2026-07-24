**File:** `.kiro/specs/pii-guard/requirements.md`
**Module:** `internal/piiguard/`
**Tool:** `piiguard/scan`

# Requirements: PII-Guard Module (Privacy & Compliance Scanner)

## Glossary

- **PII_Detector**: core engine that scans files for PII patterns using regex + entropy heuristics
- **PII_Finding**: a detected potential PII with file path, line number, pattern type, severity, and matched text
- **Entropy_Analyzer**: computes Shannon entropy on high-entropy strings to flag potential secrets/tokens
- **PII_Pattern**: a named regex pattern + severity + category (e.g. `email`, `credit_card`, `aws_key`)
- **Severity**: `"low"` (email/phone), `"medium"` (IP/internal URL), `"high"` (SSN/token), `"critical"` (credit card/credentials)
- **LLM_Enricher**: async enrichment via shared `LLMBackend` for ambiguous findings

## Requirements (EARS Format)

### REQ-PG-1: PII Pattern Detection

- **[Ubiquitous]** THE PII_Detector SHALL scan files in `directory_path` matching these extensions: `.go`, `.py`, `.js`, `.ts`, `.java`, `.rb`, `.php`, `.yaml`, `.yml`, `.json`, `.tf`, `.env`, `.properties`, `.ini`, `.cfg`, `.conf`, `.txt`, `.md`.
- **[Ubiquitous]** THE PII_Detector SHALL skip `vendor/`, `node_modules/`, `.git/`, `__pycache__/`, `.venv/`, and `.terraform/` directories.
- **[Ubiquitous]** THE PII_Detector SHALL reject any individual file >2MB by logging a warning and skipping it.
- **[Ubiquitous]** THE PII_Detector SHALL apply the following built-in patterns:
  - `email` — RFC 5322 simplified email regex → severity `low`
  - `phone` — E.164 and common formats (`+1 (555) 123-4567`) → severity `low`
  - `credit_card` — Visa/MC/Amex/Discover with Luhn checksum validation → severity `critical`
  - `ssn` — US SSN `XXX-XX-XXXX` format → severity `high`
  - `aws_access_key` — `AKIA[0-9A-Z]{16}` → severity `critical`
  - `aws_secret_key` — `(?i)aws(.{0,20})?(?:secret|key|access).{0,20}[A-Za-z0-9/+=]{40}` → severity `critical`
  - `github_token` — `gh[pousr]_[A-Za-z0-9_]{36,251}` → severity `critical`
  - `generic_api_key` — `(?i)(api[_-]?key|apikey|token|secret).{0,20}[A-Za-z0-9_\-\.]{16,64}` → severity `high`
  - `password_field` — `(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]` → severity `critical`
  - `private_key` — PEM-encoded private key header (`-----BEGIN [A-Z ]+ PRIVATE KEY-----`) → severity `critical`
  - `jwt_token` — `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` → severity `high`
  - `ip_address` — Internal IPv4 ranges (`10.x`, `172.16-31.x`, `192.168.x`) → severity `medium`
  - `connection_string` — ODBC/JDBC connection strings with credentials → severity `critical`
- **[State-Driven]** WHILE scanning, IF a file has a binary MIME type (detected via `http.DetectContentType` on first 512 bytes), THE PII_Detector SHALL skip it silently.

### REQ-PG-2: Entropy-Based Detection

- **[Ubiquitous]** THE Entropy_Analyzer SHALL compute Shannon entropy for string literals longer than 20 characters found in source code.
- **[Ubiquitous]** THE Entropy_Analyzer SHALL flag strings with entropy ≥ 4.5 as potential secrets.
- **[State-Driven]** WHILE scanning, IF a string matches a named PII pattern, entropy check SHALL be skipped (pattern match takes precedence).
- **[Event-Driven]** WHEN no named pattern matches AND entropy ≥ 4.5, THE Entropy_Analyzer SHALL emit a finding with pattern type `high_entropy_string` and severity `medium`.

### REQ-PG-3: Finding Deduplication and Scoring

- **[Ubiquitous]** THE PII_Detector SHALL deduplicate findings by `(file_path, line_number, pattern_type)` — the first occurrence wins.
- **[Ubiquitous]** THE PII_Detector SHALL NOT flag findings inside `_test.go`, `_spec.rb`, `test_*.py`, `*.test.js`, `*.spec.ts`, or `*_test.py` files.
- **[Ubiquitous]** THE PII_Detector SHALL NOT flag findings on lines that contain ONLY a comment (`//`, `#`, `--`).
- **[Unwanted]** THE PII_Detector SHALL NOT scan binary files, images, archives (`.zip`, `.tar`, `.gz`, `.jar`), or lock files (`.lock`, `package-lock.json`, `yarn.lock`).

### REQ-PG-4: MCP Tool Integration

- **[Ubiquitous]** THE Module SHALL expose `piiguard/scan` accepting:
  - `directory_path` (required, string) — root of the scan
  - `severity_threshold` (optional, string, default `"low"`) — minimum severity to report: `low`, `medium`, `high`, `critical`
  - `patterns` (optional, string array) — subset of pattern names to enable; if omitted, all patterns apply
  - `entropy_check` (optional, bool, default `true`) — enable entropy-based detection
- **[Ubiquitous]** THE Handler SHALL register via `RegisterPIIGuard(dispatcher, handler)`.
- **[Ubiquitous]** THE Handler SHALL validate `directory_path` is non-empty and exists → error `-32602` if missing.
- **[Ubiquitous]** THE Handler SHALL validate `severity_threshold` is one of `low`, `medium`, `high`, `critical` → error `-32602` if invalid.
- **[Ubiquitous]** THE response SHALL contain `findings`, `summary` (count per pattern type), `scan_time_ms`, and optionally `request_id`.

### REQ-PG-5: Async LLM Verification (Optional Enrichment)

- **[Event-Driven]** WHEN the Handler has both an `LLMBackend` AND an `rpc.Notifier` AND critical/high findings exist AND the request carries a client session ID, THE Handler SHALL return findings **immediately** and launch `startBackgroundVerification()` in a detached goroutine.
- **[Ubiquitous]** THE initial response SHALL include a `request_id` for client-side correlation.
- **[Ubiquitous]** THE background goroutine SHALL group findings by file, ask the LLM to confirm true/false positive for each, and push a `notifications/message` with `PIIVerification` payload.
- **[Unwanted]** IF the LLM errors or times out, THE Handler SHALL silently drop the notification.
- **[Unwanted]** IF the `rpc.Notifier` is nil or `rpc.ClientID` is empty, THE Handler SHALL return findings without enrichment.

### REQ-PG-6: Read-Only Guarantee

- **[Ubiquitous]** THE Module SHALL NOT write, modify, or delete files. All operations are `os.ReadFile` + regex matching.
- **[Unwanted]** THE Module SHALL NOT send raw file contents to the LLM — only context snippets (50 chars before/after the match).

### REQ-PG-7: Error Wrapping and Propagation

- **[Ubiquitous]** THE Module SHALL wrap all internal errors with `fmt.Errorf("context: %w", err)`.
- **[Ubiquitous]** Parse/validation errors → `-32602` (Invalid Params). Filesystem errors → `-32603` (Internal Error).
- **[Unwanted]** THE Module SHALL NOT use bare `errors.New` across the handler boundary.

## Acceptance Criteria

| ID | Trigger | Expected Result |
|----|---------|-----------------|
| PCA-1 | `.go` file with `const AWS_KEY = "AKIA1234567890123456"` | 1 finding: `aws_access_key`, severity `critical`, line matches |
| PCA-2 | File with credit card `4111-1111-1111-1111` | 1 finding: `credit_card`, severity `critical`, Luhn valid |
| PCA-3 | File with `"password": "supersecret123"` in JSON | 1 finding: `password_field`, severity `critical` |
| PCA-4 | `.env` file with `GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | 1 finding: `github_token`, severity `critical` |
| PCA-5 | Go file with email `test@example.com` in a comment `// contact test@example.com` | 1 finding: `email`, severity `low` |
| PCA-6 | `_test.go` file with embedded AWS key | 0 findings (test file excluded) |
| PCA-7 | Empty directory | Empty findings, scan_time_ms > 0 |
| PCA-8 | `severity_threshold=critical` and only emails present | Empty findings (filtered by threshold) |
| PCA-9 | `directory_path=""` | Error `-32602` |
| PCA-10 | File with high-entropy string `aB3dE5fG7hI9kL1mN2oP4qR6sT8uV0wX2yZ4` | 1 finding: `high_entropy_string`, severity `medium` |
| PCA-11 | LLM + Notifier + session, 3 findings | Initial response has `request_id`; exactly 1 `PIIVerification` notification |
| PCA-12 | File >2MB | File skipped, warning logged, scan continues |
