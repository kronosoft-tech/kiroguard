**File:** `.kiro/specs/lambdaguard/tasks.md`
**Module:** `internal/lambdaguard/`
**Tool:** `lambdaguard/analyze`

# Implementation Tasks: LambdaGuard Module

**Alcance de esta spec:** Cubre EXCLUSIVAMENTE `internal/lambdaguard/`. No modifiques ni analices otros modulos existentes.

---

## Tasks

### Task 1: Define types (`types.go`)

- **Req:** REQ-LG-1, REQ-LG-5
- **Files:** `internal/lambdaguard/types.go`
- **Goal:** Define all shared types for the module.

#### Step-by-step

1. **Create `internal/lambdaguard/types.go`** with:
   - `LambdaConfig` struct (11 fields as defined in design)
   - `LambdaFinding` struct: `FunctionName`, `SourceFile`, `CheckID`, `Severity`, `Category`, `Message`, `Remediation`, `CurrentValue` — json tags
   - `Summary` struct: `TotalFunctions`, `TotalFindings`, `BySeverity`, `ByCategory`, `ScanTimeMs`, `FilesScanned` — json tags
   - `IAMStatement` struct: `Effect`, `Action`, `Resource` — json tags
   - `VPCConfig` struct: `SubnetIDs`, `SecurityGroupIDs` — json tags
   - `Metrics` struct with `AnalyzesTotal`, `FunctionsTotal`, `FindingsTotal`, `CriticalFindings` — `atomic.Int64`
   - `MetricsSnapshot` struct (immutable copy)
   - `Params` struct: `DirectoryPath`, `Checks`, `SeverityThreshold` — json tags
   - `Response` struct: `Functions`, `Findings`, `Summary`, `ScanTimeMs` — json tags

2. **Write minimal test in `types_test.go`:**
   - `TestMetricsSnapshot` — atomic values copied correctly

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/`

---

### Task 2: Implement IaC parser (`parser.go`)

- **Req:** REQ-LG-1
- **Files:** `internal/lambdaguard/parser.go`, `internal/lambdaguard/parser_test.go`
- **Goal:** Parse SAM, Serverless Framework, Terraform, and CDK files into `[]LambdaConfig`.

#### Step-by-step

1. **Create `internal/lambdaguard/parser.go`** with:
   - `ParseLambdaConfigs(dir string) ([]LambdaConfig, error)`:
     1. Walk dir, skip excluded dirs
     2. For each IaC file, dispatch to the appropriate format parser
     3. Aggregate results
   - `parseSAM(path string) ([]LambdaConfig, error)` — YAML unmarshal, walk `Resources`
   - `parseServerless(path string) ([]LambdaConfig, error)` — YAML unmarshal, walk `functions`
   - `parseTerraform(path string) ([]LambdaConfig, error)` — regex-based resource block extraction
   - `parseCDK(path string) ([]LambdaConfig, error)` — regex heuristic for `new lambda.Function(`
   - `isIaCFile(path string) bool` — matches known IaC filenames/extensions
   - Helper: `parseYAMLGraceful(path string, target interface{}) error` — unmarshal with lenient options

2. **Write tests in `parser_test.go`** (use `t.TempDir()` + `os.WriteFile`):
   - `TestParseSAM_Basic` — SAM template with one Lambda → 1 config, correct timeout/memory
   - `TestParseSAM_NoFunctions` — SAM template without Lambda resources → empty
   - `TestParseServerless_Basic` — serverless.yml with one function
   - `TestParseTerraform_Basic` — Terraform `aws_lambda_function` resource
   - `TestParseCDK_TypeScript` — `.ts` file with `new lambda.Function(` → heuristic match
   - `TestParseCDK_JavaScript` — `.js` file with `new Function(` → heuristic match
   - `TestParseLambdaConfigs_MixedFiles` — SAM + Terraform in same dir → combined
   - `TestParseLambdaConfigs_NoIaCFiles` → empty
   - `TestParseLambdaConfigs_EmptyDirectory`
   - `TestParseLambdaConfigs_FileOver5MB` → skipped
   - `TestParseLambdaConfigs_NestedDirectories` — recurse into subdirs
   - `TestIsIaCFile` — known names return true

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/ -run 'Test(Parse|IsIaC)'`

---

### Task 3: Implement IAM role analyzer (`iam.go`)

- **Req:** REQ-LG-2
- **Files:** `internal/lambdaguard/iam.go`, `internal/lambdaguard/iam_test.go`
- **Goal:** Detect over-privileged IAM policies attached to Lambda functions.

#### Step-by-step

1. **Create `internal/lambdaguard/iam.go`** with:
   - `AnalyzeIAM(cfg *LambdaConfig) []LambdaFinding`:
     1. Check inline policies for `Action: "*"` or `Resource: "*"` → critical
     2. Flag managed policy ARNs → medium (review)
     3. Return findings with function context

2. **Write tests in `iam_test.go`:**
   - `TestAnalyzeIAM_InlineWildcardAction` — `Action: ["*"]` → critical
   - `TestAnalyzeIAM_InlineWildcardResource` — `Resource: "*"` → critical
   - `TestAnalyzeIAM_ManagedPolicy` — `ManagedPolicyArns` present → medium
   - `TestAnalyzeIAM_NoIssues` — specific actions only → no findings
   - `TestAnalyzeIAM_EmptyRole` — no statements → no findings

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/ -run 'TestAnalyzeIAM'`

---

### Task 4: Implement environment variable scanner (`env.go`)

- **Req:** REQ-LG-3
- **Files:** `internal/lambdaguard/env.go`, `internal/lambdaguard/env_test.go`
- **Goal:** Scan Lambda environment variables for hardcoded secrets.

#### Step-by-step

1. **Create `internal/lambdaguard/env.go`** with:
   - `ScanEnvVars(cfg *LambdaConfig) []LambdaFinding`:
     1. Iterate over `cfg.Environment` key-value pairs
     2. Skip values matching `{{resolve:secretsmanager:...}}`, `{{resolve:ssm:...}}`, or CloudFormation `!Ref`/`!Sub` patterns
     3. Apply PII-Guard-style regex patterns (email, aws_key, generic_api_key, password_field)
     4. Apply entropy check on values > 20 chars with ≥ 4.5 threshold
     5. Redact matched values to `****` in findings
     6. Return findings with `category: "security"`, `check_id: "SECRET"` or `HIGH_ENTROPY`

2. **Write tests in `env_test.go`:**
   - `TestScanEnvVars_AWSKey` — `DB_PASSWORD=AKIA1234567890123456` → critical
   - `TestScanEnvVars_Email` — `CONTACT=user@example.com` → low
   - `TestScanEnvVars_SecretsManagerRef` — `DB_PASSWORD={{resolve:secretsmanager:...}}` → skipped
   - `TestScanEnvVars_HighEntropy` — >20 chars with high entropy → medium
   - `TestScanEnvVars_NoSecrets` — clean env vars → empty
   - `TestScanEnvVars_EmptyEnv` — no env vars → empty
   - `TestScanEnvVars_ValueRedacted` — finding shows `****` not actual value

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/ -run 'TestScanEnvVars'`

---

### Task 5: Implement best practice checker (`bestpractices.go`)

- **Req:** REQ-LG-4
- **Files:** `internal/lambdaguard/bestpractices.go`, `internal/lambdaguard/bestpractices_test.go`
- **Goal:** Evaluate each Lambda function against 12 best-practice checks.

#### Step-by-step

1. **Create `internal/lambdaguard/bestpractices.go`** with:
   - `Check` type: `func(cfg *LambdaConfig) *LambdaFinding`
   - `var BestPracticeChecks = []Check{...}` — all 12 checks from REQ-LG-4 table
   - `ApplyBestPractices(cfg *LambdaConfig, checkIDs []string) []LambdaFinding`:
     - If `checkIDs` is nil/empty, run all checks
     - Otherwise, filter by check ID (e.g. `"LG-1"`, `"LG-2"`)
   - Each check implementation:
     - `checkTimeoutTooLong` (LG-1): `cfg.Timeout > 900`
     - `checkTimeoutDefault` (LG-2): `cfg.Timeout == 3`
     - `checkMemoryTooHigh` (LG-3): `cfg.MemorySize > 3008`
     - `checkMemoryTooLow` (LG-4): `cfg.MemorySize < 128`
     - `checkNoDLQ` (LG-5): `cfg.DLQTarget == "" && cfg.Timeout > 60`
     - `checkNoVPCForRDS` (LG-6): `cfg.VPCConfig == nil` AND IAM has `rds:*` or `elasticache:*`
     - `checkNoReservedConcurrency` (LG-7): `cfg.ReservedConcurrency == -1`
     - `checkRuntimeEOL` (LG-8): runtime not in supported list
     - `checkTracingNotActive` (LG-9): `cfg.TracingMode != "Active"`
     - `checkNoDescription` (LG-10): `cfg.Description == ""`
     - `checkLatestAlias` (LG-11): `cfg.Handler` contains `$LATEST`
     - `checkBothArchitectures` (LG-12): both `x86_64` and `arm64` in `cfg.Architectures`

2. **Write tests in `bestpractices_test.go`:**
   - `TestApplyBestPractices_AllPass` — config with optimal settings → 0 findings
   - `TestApplyBestPractices_TimeoutTooLong` → LG-1 finding
   - `TestApplyBestPractices_TimeoutDefault` → LG-2 finding
   - `TestApplyBestPractices_MemoryTooHigh` → LG-3 finding
   - `TestApplyBestPractices_MemoryTooLow` → LG-4 finding
   - `TestApplyBestPractices_NoDLQ` → LG-5 finding
   - `TestApplyBestPractices_NoVPCForRDS` → LG-6 finding
   - `TestApplyBestPractices_NoReservedConcurrency` → LG-7 finding
   - `TestApplyBestPractices_RuntimeEOL` → LG-8 finding
   - `TestApplyBestPractices_TracingNotActive` → LG-9 finding
   - `TestApplyBestPractices_NoDescription` → LG-10 finding
   - `TestApplyBestPractices_LatestAlias` → LG-11 finding
   - `TestApplyBestPractices_BothArchitectures` → LG-12 finding
   - `TestApplyBestPractices_FilterByCheckIDs` — only specified checks run
   - `TestApplyBestPractices_MultipleFindings` — config triggers 3 checks → 3 findings

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/ -run 'TestApplyBestPractices'`

---

### Task 6: Implement handler (`handler.go`)

- **Req:** REQ-LG-5, REQ-LG-6, REQ-LG-7
- **Files:** `internal/lambdaguard/handler.go`, `internal/lambdaguard/handler_test.go`
- **Goal:** Wire the parsers and analyzers into a JSON-RPC handler.

#### Step-by-step

1. **Create `internal/lambdaguard/handler.go`** with:
   - `LambdaGuardHandler` struct: `baseCtx`, `metrics *Metrics`, `opts Options`
   - `Options` struct with functional options:
     - `WithMetrics(m *Metrics)`
     - `WithSeverityThreshold(s string)`
     - `WithMaxFileSizeMB(n int)`
     - `WithScanTimeout(d time.Duration)`
     - `WithMetricsInterval(d time.Duration)`
   - `NewLambdaGuardHandler(ctx, opts...) *LambdaGuardHandler`
   - `Handle(ctx, params)`:
     1. Parse `Params`, validate
     2. Call `ParseLambdaConfigs(dir)` with timeout
     3. For each config: run IAM analyzer, env scanner, best practice checker
     4. Filter by `severity_threshold`
     5. Aggregate findings, build summary
     6. Return `Response`
   - `Shutdown(timeout time.Duration)`
   - `RegisterLambdaGuard(dispatcher, handler)` — registers `lambdaguard/analyze`

2. **Write tests in `handler_test.go`:**
   - `TestHandle_ValidScan` — SAM file + all checks → findings populated
   - `TestHandle_EmptyDirectoryPath` → error `-32602`
   - `TestHandle_NonexistentDirectory` → error `-32602`
   - `TestHandle_InvalidSeverityThreshold` → error `-32602`
   - `TestHandle_NoFindings` — clean configs → empty findings
   - `TestMetricsSnapshot`
   - `TestShutdown`
   - `TestOptions` — each functional option alters state

3. **Verify:** `go test -v -count=1 ./internal/lambdaguard/`

---

### Task 7: Wire into main and config (`main.go`, `config/`)

- **Req:** REQ-LG-5
- **Files:** `main.go`, `internal/config/config.go`, `internal/config/defaults.go`, `internal/config/config_test.go`
- **Goal:** Register the module in the main binary.

#### Step-by-step

1. **Add to `main.go`:**
   - Import `internal/lambdaguard`
   - Wire handler with options
   - Register via `lambdaguard.RegisterLambdaGuard(dispatcher, handler)`
   - Start metrics reporter goroutine

2. **Add to `internal/config/config.go`:**
   - `LambdaGuardConfig` struct with config fields
   - Validate in `validate()`

3. **Add to `internal/config/defaults.go`:**
   - `LambdaGuard: LambdaGuardConfig{...}` with defaults

4. **Add to `internal/rpc/mcp_test.go`:**
   - Expected tool names updated

5. **Verify:** `go build -o /dev/null .` and `go test -v -count=1 ./internal/config/`

---

## Review Workload Forecast

| Task | Files | Est. Lines | Risk |
|------|-------|-----------|------|
| Task 1: types | 2 new | ~80 | Low |
| Task 2: IaC parser | 2 new | ~400 | Medium |
| Task 3: IAM analyzer | 2 new | ~120 | Low |
| Task 4: env scanner | 2 new | ~150 | Low |
| Task 5: best practices | 2 new | ~300 | Low |
| Task 6: handler | 2 new | ~350 | Medium |
| Task 7: wiring + config | 4 modified | ~50 | Low |
| **Total** | **16** | **~1450** | **High** |

**Review slices (chained PRs):**
- PR 1: Tasks 1+3+4 (types, IAM, env) — ~350 lines, foundation + security checks
- PR 2: Task 5 (best practices) — ~300 lines, core logic
- PR 3: Task 2 (IaC parser) — ~400 lines, format support
- PR 4: Tasks 6+7 (handler + wiring) — ~400 lines, integration
