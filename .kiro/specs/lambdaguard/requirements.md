**File:** `.kiro/specs/lambdaguard/requirements.md`
**Module:** `internal/lambdaguard/`
**Tool:** `lambdaguard/analyze`

# Requirements: LambdaGuard Module (Serverless Security Analyzer)

## Glossary

- **Lambda_Config**: a parsed Lambda function definition from IaC (SAM, Serverless Framework, CDK, Terraform, CloudFormation)
- **Lambda_Finding**: a detected issue with severity, category, and remediation suggestion
- **IaC_Parser**: extracts Lambda function definitions from supported IaC formats
- **IAM_Role_Analyzer**: inspects the IAM role attached to a Lambda for over-privilege (wildcard actions/resources)
- **Env_Var_Scanner**: scans environment variables for hardcoded secrets using regex + entropy (same engine as PII-Guard)
- **Best_Practice_Checker**: validates timeout, memory, DLQ, VPC, runtime, reserved concurrency, and logging settings
- **Category**: one of `security`, `cost`, `operations`, `reliability`, `performance`
- **Severity**: `"low"`, `"medium"`, `"high"`, `"critical"`

---

## Requirements (EARS Format)

### REQ-LG-1: IaC Lambda Function Discovery

- **[Ubiquitous]** THE IaC_Parser SHALL discover Lambda function definitions in:
  - `template.yaml` / `template.yml` (AWS SAM) — `AWS::Serverless::Function` resources
  - `serverless.yaml` / `serverless.yml` (Serverless Framework) — `functions.*` entries
  - `*.tf` / `*.tf.json` (Terraform) — `resource "aws_lambda_function"` blocks
  - `*.ts` / `*.js` (CDK / custom IaC) — heuristic detection of `new lambda.Function` / `new Function`
- **[Ubiquitous]** THE IaC_Parser SHALL reject any individual file >5MB by logging a warning and skipping it.
- **[Ubiquitous]** THE IaC_Parser SHALL skip `vendor/`, `node_modules/`, `.git/`, `.terraform/`, `cdk.out/`.
- **[Ubiquitous]** THE IaC_Parser SHALL return a list of `LambdaConfig` with:
  - `FunctionName` — logical resource name
  - `SourceFile` — IaC file path
  - `Runtime` — e.g. `nodejs20.x`, `python3.12`, `provided.al2023`
  - `Timeout` — seconds (int)
  - `MemorySize` — MB (int)
  - `RoleARN` or `RoleStatements` — inline IAM statements if available
  - `Environment` — map of env vars (redacted secrets shown as `****`)
  - `DLQTarget` — ARN or `null`
  - `VPCConfig` — subnet IDs, security group IDs, or `null`
  - `ReservedConcurrency` — int or `-1` if not set
  - `TracingMode` — `Active`, `PassThrough`, or empty
  - `Architectures` — `x86_64` or `arm64`
  - `Handler` — function handler string
  - `Description` — free text description

### REQ-LG-2: Over-Privileged IAM Role Detection

- **[Ubiquitous]** THE IAM_Role_Analyzer SHALL inspect IAM policies defined inline in the Lambda resource or referenced via `AWS::IAM::Role`.
- **[Ubiquitous]** THE IAM_Role_Analyzer SHALL flag `"Action": "*"` or `"Resource": "*"` as `critical` severity in the `security` category.
- **[Ubiquitous]** THE IAM_Role_Analyzer SHALL flag managed policies attached to the role (`ManagedPolicyArns`) for review as `medium` severity in the `security` category.
- **[Unwanted]** THE IAM_Role_Analyzer SHALL NOT make any live AWS API calls — analysis is purely local.

### REQ-LG-3: Environment Variable Secrets Scanning

- **[Ubiquitous]** THE Env_Var_Scanner SHALL apply the same regex patterns from PII-Guard to environment variable values in Lambda configs.
- **[Ubiquitous]** THE Env_Var_Scanner SHALL apply Shannon entropy ≥ 4.5 detection for env var values > 20 characters.
- **[Ubiquitous]** THE Env_Var_Scanner SHALL redact actual secret values in the finding output, showing only `****`.
- **[Unwanted]** THE Env_Var_Scanner SHALL NOT flag env vars that reference AWS Parameters/Secrets Manager (pattern: `{{resolve:secretsmanager:...}}` or `!Ref` to a dynamic reference).

### REQ-LG-4: Best Practice Validation

- **[Ubiquitous]** THE Best_Practice_Checker SHALL evaluate each `LambdaConfig` against the following checks:

| # | Check | Condition | Severity | Category |
|---|-------|-----------|----------|----------|
| 1 | **Timeout > 15min** | `Timeout > 900` | `high` | `operations` |
| 2 | **Timeout == 3s (default)** | `Timeout == 3` | `medium` | `reliability` |
| 3 | **Memory > 3008 MB** | `MemorySize > 3008` | `low` | `cost` |
| 4 | **Memory < 128 MB** | `MemorySize < 128` | `high` | `reliability` |
| 5 | **No DLQ configured** | `DLQTarget == null` AND `Timeout > 60` | `medium` | `reliability` |
| 6 | **No VPC for RDS-like actions** | `VPCConfig == null` AND role has `rds:*` or `elasticache:*` | `high` | `security` |
| 7 | **Reserved concurrency not set** | `ReservedConcurrency == -1` OR absent | `low` | `cost` |
| 8 | **Runtime possibly EOL** | Runtime older than current supported versions | `medium` | `operations` |
| 9 | **Tracing not active** | `TracingMode != "Active"` | `low` | `operations` |
| 10 | **No description** | `Description == ""` | `low` | `operations` |
| 11 | **Handler uses latest alias** | Handler references `$LATEST` | `medium` | `reliability` |
| 12 | **Both x86_64 + arm64 architectures** | `Architectures` contains both | `low` | `cost` |

### REQ-LG-5: MCP Tool Integration

- **[Ubiquitous]** THE Module SHALL expose `lambdaguard/analyze` accepting:
  - `directory_path` (required, string) — root to scan for IaC files
  - `checks` (optional, string array) — subset of check IDs to run; all if omitted
  - `severity_threshold` (optional, string, default `"low"`) — minimum severity to report
- **[Ubiquitous]** THE Handler SHALL register via `RegisterLambdaGuard(dispatcher, handler)`.
- **[Ubiquitous]** THE Handler SHALL validate `directory_path` is non-empty and exists → error `-32602`.
- **[Ubiquitous]** THE Handler SHALL validate `severity_threshold` → error `-32602` if invalid.
- **[Ubiquitous]** THE response SHALL contain `functions` (list of discovered functions), `findings` (aggregated), `summary` (per severity/category), `scan_time_ms`.

### REQ-LG-6: Read-Only Guarantee

- **[Ubiquitous]** THE Module SHALL NOT write, modify, or delete files. All operations are `os.ReadFile` + YAML/JSON/`go/parser` parsing.
- **[Unwanted]** THE Module SHALL NOT make any live AWS API calls.

### REQ-LG-7: Error Wrapping and Propagation

- **[Ubiquitous]** THE Module SHALL wrap all internal errors with `fmt.Errorf("context: %w", err)`.
- **[Ubiquitous]** Parse/validation errors → `-32602`. Filesystem errors → `-32603`.
- **[Unwanted]** THE Module SHALL NOT use bare `errors.New` across the handler boundary.

---

## Acceptance Criteria

| ID | Trigger | Expected Result |
|----|---------|-----------------|
| LCA-1 | SAM `template.yaml` with `AWS::Serverless::Function`, `Timeout: 900` | 1 function discovered; 1 finding: timeout > 900 is high |
| LCA-2 | Serverless `serverless.yml` with inline IAM `Action: "*"` | 1 function discovered; 1 finding: wildcard IAM critical |
| LCA-3 | Terraform `lambda.tf` with `aws_lambda_function` + env vars containing `AKIA...` | 1 function + 1 secret finding (redacted) |
| LCA-4 | Lambda with `DLQTarget` absent + timeout 120s | 1 finding: no DLQ for long-running function |
| LCA-5 | Lambda with VPC null + role having `rds:*` | 1 finding: VPC missing for RDS access |
| LCA-6 | Empty directory | Empty functions + findings, scan_time_ms > 0 |
| LCA-7 | File >5MB | File skipped, warning logged, scan continues |
| LCA-8 | `directory_path=""` | Error `-32602` |
| LCA-9 | CDK `.ts` file with `new lambda.Function` | 1 function discovered (heuristic) |
