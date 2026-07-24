**File:** `.kiro/specs/pii-guard/tasks.md`
**Module:** `internal/piiguard/`
**Tool:** `piiguard/scan`

# Implementation Tasks: PII-Guard Module

**Alcance de esta spec:** Cubre EXCLUSIVAMENTE `internal/piiguard/`. No modifiques ni analices `internal/cleanarch/`, `internal/envguard/`, `internal/vulnscanner/`, `internal/iamguard/`, ni `internal/finops/`.

---

## Tasks

### Task 1: Define types and pattern registry (`types.go`, `patterns.go`)

- **Req:** REQ-PG-1, REQ-PG-4
- **Files:** `internal/piiguard/types.go`, `internal/piiguard/patterns.go`, `internal/piiguard/patterns_test.go`
- **Goal:** Define the shared types and built-in PII pattern registry.

#### Step-by-step

1. **Create `internal/piiguard/types.go`** with:
   - `PIIFinding` struct: `FilePath`, `LineNumber`, `PatternType`, `Severity`, `MatchSample`, `Context` — json tags
   - `Summary` struct: `TotalFindings`, `BySeverity`, `ByPatternType`, `ScanTimeMs`, `FilesScanned`, `FilesSkipped` — json tags
   - `VerificationResult` struct: `RequestID`, `Verdicts`, `GeneratedAt` — json tags
   - `FindingVerdict` struct: `FilePath`, `LineNumber`, `PatternType`, `IsTruePositive`, `LLMReason` — json tags
   - `Metrics` struct with `ScansTotal`, `FindingsTotal`, `CriticalFindings`, `VerificationsOK`, `VerificationsFailed` — `atomic.Int64`
   - `MetricsSnapshot` struct (immutable copy)
   - `PIIParams` struct: `DirectoryPath`, `SeverityThreshold`, `Patterns`, `EntropyCheck` — json tags
   - `PIIResponse` struct: `Findings`, `Summary`, `ScanTimeMs`, `RequestID` — json tags
   - `PIIPattern` struct: `Name`, `Severity`, `Category`, `Regex`, `Description`

2. **Create `internal/piiguard/patterns.go`** with:
   - `var BuiltinPatterns []PIIPattern` — 14 patterns as defined in the design doc:
     - `email`: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
     - `phone`: `\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}`
     - `credit_card`: `\b(?:\d{4}[-\s]?){3}\d{4}\b` (Luhn validation done at scan time)
     - `ssn`: `\b\d{3}-\d{2}-\d{4}\b`
     - `aws_access_key`: `AKIA[0-9A-Z]{16}`
     - `aws_secret_key`: `(?i)aws(.{0,20})?(?:secret|key|access).{0,20}[A-Za-z0-9/+=]{40}`
     - `github_token`: `gh[pousr]_[A-Za-z0-9_]{36,251}`
     - `generic_api_key`: `(?i)(?:api[_-]?key|apikey|token|secret).{0,20}['\"][A-Za-z0-9_\-\.]{16,64}['\"]`
     - `password_field`: `(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]`
     - `private_key`: `-----BEGIN [A-Z ]+ PRIVATE KEY-----`
     - `jwt_token`: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`
     - `ip_address`: `\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`
     - `connection_string`: `(?i)(?:jdbc|odbc|mongodb|postgresql|mysql)://[^\s]+`
     - `high_entropy_string`: (computed, not regex — used as fallback)
   - `GetPatterns(names []string) []PIIPattern` — filter by names, or return all if nil
   - `luhnCheck(s string) bool` — Luhn checksum for credit card validation
   - Compile-time check: patterns compile successfully at init

3. **Write tests in `patterns_test.go`**:
   - `TestPatterns_Compile` — all 14 patterns compile
   - `TestEmailPattern` — matches `user@example.com`, rejects `not-an-email`
   - `TestCreditCardPattern` — matches `4111-1111-1111-1111`, rejects `1234-5678-9012-3456` (Luhn invalid)
   - `TestAWSAccessKey` — matches `AKIA1234567890123456`
   - `TestSSN` — matches `123-45-6789`
   - `TestJWT` — matches valid JWT structure
   - `TestPrivateKey` — matches `-----BEGIN RSA PRIVATE KEY-----`
   - `TestGetPatterns_Filter` — subset by name
   - `TestGetPatterns_All` — nil returns all
   - `TestLuhnCheck_Valid` / `_Invalid`

4. **Verify:** `go test -v -count=1 ./internal/piiguard/ -run 'Test(Patterns|Email|Credit|AWS|SSN|JWT|Private|GetPatterns|Luhn)'`

---

### Task 2: Implement entropy analyzer (`entropy.go`)

- **Req:** REQ-PG-2
- **Files:** `internal/piiguard/entropy.go`, `internal/piiguard/entropy_test.go`
- **Goal:** Compute Shannon entropy for string literals.

#### Step-by-step

1. **Create `internal/piiguard/entropy.go`** with:
   - `ShannonEntropy(s string) float64` — computes `-sum(p_i * log2(p_i))` where `p_i = freq(c) / len(s)`
   - `IsHighEntropy(s string, threshold float64) bool` — returns `ShannonEntropy(s) >= threshold`
   - `extractStringLiterals(content []byte) []string` — naive extraction of quoted strings (`"..."`, `'...'`, backtick)

2. **Write tests in `entropy_test.go`**:
   - `TestShannonEntropy_Low` — `"hello world"` → low
   - `TestShannonEntropy_High` — `"aB3dE5fG7hI9kL1mN2oP4qR6sT8uV0wX2yZ4"` → ≥ 4.5
   - `TestShannonEntropy_Empty` → 0
   - `TestIsHighEntropy_AboveThreshold`
   - `TestIsHighEntropy_BelowThreshold`
   - `TestExtractStringLiterals_GoSource` — extracts double-quoted strings
   - `TestExtractStringLiterals_None` — no quotes → empty

3. **Verify:** `go test -v -count=1 ./internal/piiguard/ -run 'Test(Shannon|IsHighEntropy|ExtractString)'`

---

### Task 3: Implement the file scanner (`detector.go`)

- **Req:** REQ-PG-1, REQ-PG-2, REQ-PG-3
- **Files:** `internal/piiguard/detector.go`, `internal/piiguard/detector_test.go`
- **Goal:** Walk directory, apply patterns + entropy, return findings.

#### Step-by-step

1. **Create `internal/piiguard/detector.go`** with:
   - `ScanFiles(dir string, patterns []PIIPattern, entropyCheck bool) ([]PIIFinding, *Summary, error)`:
     1. Walk dir with `fs.WalkDir`, filter by extension list, skip excluded dirs
     2. For each file: check `os.Stat` size ≤ `maxFileSize` (config default 2MB)
     3. Check MIME type (first 512 bytes via `http.DetectContentType`) — skip if binary
     4. Read file, scan line by line against all active patterns
     5. For each match: record `PIIFinding` with 40-char match sample (middle redacted with `[...]`) and 50-char context
     6. If `entropyCheck` is true AND no pattern matched AND line has string literals: compute entropy, flag if ≥ threshold
     7. Deduplicate by `(file_path, line_number, pattern_type)`
     8. Skip test files and comment-only lines
     9. Build `Summary`

2. **Write tests in `detector_test.go`**:
   - `TestScanFiles_WithAWSKey`
   - `TestScanFiles_WithCreditCard`
   - `TestScanFiles_WithEmail`
   - `TestScanFiles_WithPasswordField`
   - `TestScanFiles_SkipsTestFiles`
   - `TestScanFiles_SkipsVendorDir`
   - `TestScanFiles_SkipsNodeModules`
   - `TestScanFiles_SkipsBinaryFile`
   - `TestScanFiles_FileOver2MB` — create >2MB file → skipped
   - `TestScanFiles_EmptyDirectory`
   - `TestScanFiles_NoFindings`
   - `TestScanFiles_Deduplicates`
   - `TestScanFiles_EntropyFindings` — high entropy string detected
   - `TestScanFiles_ThresholdFilter` — only critical findings returned
   - `TestScanFiles_NonexistentDir` → error

3. **Verify:** `go test -v -count=1 ./internal/piiguard/ -run 'TestScanFiles'`

---

### Task 4: Implement handler (`handler.go`)

- **Req:** REQ-PG-4, REQ-PG-5, REQ-PG-6, REQ-PG-7
- **Files:** `internal/piiguard/handler.go`, `internal/piiguard/handler_test.go`
- **Goal:** Wire the scanner into a JSON-RPC handler with optional async enrichment.

#### Step-by-step

1. **Create `internal/piiguard/handler.go`** with:
   - `PIIGuardHandler` struct with:
     - `baseCtx context.Context`
     - `llm llm.LLMBackend` (optional)
     - `notifier rpc.Notifier` (optional)
     - `metrics *Metrics`
     - `opts PIIGuardOptions`
   - `PIIGuardOptions` struct with functional options:
     - `WithLLM(llm llm.LLMBackend)`
     - `WithNotifier(n rpc.Notifier)`
     - `WithMetrics(m *Metrics)`
     - `WithSeverityThreshold(s string)`
     - `WithMaxFileSizeMB(n int)`
     - `WithEntropyThreshold(f float64)`
     - `WithEnrichTimeout(d time.Duration)`
     - `WithScanTimeout(d time.Duration)`
     - `WithMaxConcurrent(n int)`
     - `WithMetricsInterval(d time.Duration)`
   - `NewPIIGuardHandler(ctx context.Context, opts ...PIIGuardOption) *PIIGuardHandler`
   - `Handle(ctx context.Context, params json.RawMessage) (interface{}, error)`:
     1. Parse `PIIParams` from params
     2. Validate: `directory_path` non-empty and exists; `severity_threshold` one of valid values
     3. Select patterns based on `params.Patterns` (or all)
     4. Apply `severity_threshold` to filter
     5. Call `ScanFiles(dir, patterns, entropyCheck)` with timeout
     6. Increment `ScansTotal`, `FindingsTotal`, `CriticalFindings`
     7. If LLM + Notifier + session + crit/high findings exist: launch `startBackgroundVerification()`
     8. Return `PIIResponse`
   - `startBackgroundVerification(ctx context.Context, findings []PIIFinding, requestID string)`:
     - Group findings by file
     - For each group: call LLM with snippet context
     - Parse verdict (true positive / false positive)
     - Push `VerificationResult` via notifier
   - `Shutdown(timeout time.Duration)` — wait group + drain

2. **Write tests in `handler_test.go`**:
   - `TestHandle_ValidScan`
   - `TestHandle_EmptyDirectoryPath` → error `-32602`
   - `TestHandle_InvalidSeverityThreshold` → error `-32602`
   - `TestHandle_NonexistentDirectory` → error `-32602`
   - `TestHandle_WithEnrichment` — mock LLM + Notifier → response has `request_id`
   - `TestHandle_NoLLM` — enrichment skipped
   - `TestMetricsSnapshot` — atomic values copied correctly
   - `TestShutdown` — blocks until timeout
   - `TestOptions` — each functional option alters state
   - `TestStartBackgroundVerification` — notifier receives `VerificationResult`
   - `TestStartBackgroundVerification_LLMError` — no notification

3. **Verify:** `go test -v -count=1 ./internal/piiguard/`

---

### Task 5: Wire into main and config (`main.go`, `config/`)

- **Req:** REQ-PG-4
- **Files:** `main.go`, `internal/config/config.go`, `internal/config/defaults.go`, `internal/config/config_test.go`
- **Goal:** Register the module in the main binary.

#### Step-by-step

1. **Add to `main.go`:**
   - Import `internal/piiguard`
   - After other module setups: `piiguard.RegisterPIIGuard(dispatcher, piiguardHandler)`
   - Wire metrics reporter goroutine

2. **Add to `internal/config/config.go`:**
   - `PIIGuardConfig` struct with fields matching the design config section
   - Validate in `validate()`: `severity_threshold` one of `low/medium/high/critical`; fields > 0

3. **Add to `internal/config/defaults.go`:**
   - `PIIGuard: PIIGuardConfig{...}` with defaults

4. **Add to `internal/rpc/mcp_test.go`:**
   - Expected tool names updated

5. **Verify:** `go build -o /dev/null .` and `go test -v -count=1 ./internal/config/`

---

## Review Workload Forecast

| Task | Files | Est. Lines | Risk |
|------|-------|-----------|------|
| Task 1: types + patterns | 3 new | ~220 | Low |
| Task 2: entropy | 2 new | ~100 | Low |
| Task 3: scanner | 2 new | ~350 | Medium |
| Task 4: handler | 2 new | ~400 | Medium |
| Task 5: wiring + config | 4 modified | ~50 | Low |
| **Total** | **13** | **~1120** | **High** |

**Review slices (chained PRs):**
- PR 1: Tasks 1+2 (types, patterns, entropy) — ~320 lines, foundations
- PR 2: Task 3 (scanner) — ~350 lines, core logic
- PR 3: Tasks 4+5 (handler + wiring) — ~450 lines, integration
