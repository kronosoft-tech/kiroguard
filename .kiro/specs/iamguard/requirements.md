**File:** `.kiro/specs/iamguard/requirements.md`
**Module:** `internal/iamguard/`
**Tool:** `iamguard/analyze`

# Requirements: IAM-Guard Module (Least Privilege Enforcer)

## Glossary

- **SDK_Analyzer**: parses `.go` files via `go/parser` to detect AWS SDK v2 imports and client method calls
- **IaC_Scanner**: scans IaC files for over-privileged `Action: *` / `Resource: *` IAM statements
- **AWS_Action**: a detected SDK call mapped to IAM action format (e.g. `s3:GetObject`)
- **IAM_Wildcard**: a finding for `Action: "*"` or `Resource: "*"` — risk level "critical"
- **IAM_Policy_Generator**: async LLM enrichment via the shared `LLMBackend` interface

## Requirements (EARS Format)

### REQ-IG-1: Go SDK Call Analysis

- **[Ubiquitous]** THE SDK_Analyzer SHALL walk all `.go` files recursively within `directory_path`, excluding `_test.go` and `vendor/`.
- **[Ubiquitous]** THE SDK_Analyzer SHALL parse each file with `go/parser`, first with `parser.ImportsOnly`, then full AST on files with AWS SDK imports.
- **[Ubiquitous]** THE SDK_Analyzer SHALL detect imports matching `github.com/aws/aws-sdk-go-v2/service/<service>`.
- **[Ubiquitous]** THE SDK_Analyzer SHALL track variables assigned via `<svc>.NewFromConfig(cfg)` and identify method calls on those clients (local-variable pattern only).
- **[Ubiquitous]** THE SDK_Analyzer SHALL map each call to `<service>:<Method>` (e.g. `s3.Client.GetObject` → `s3:GetObject`).
- **[Ubiquitous]** THE SDK_Analyzer SHALL produce deduplicated `[]AWSAction` with call-site count and full `[]SDKUsage`.
- **[State-Driven]** WHILE walking, IF a file has syntax errors, THE SDK_Analyzer SHALL skip it silently.
- **[Event-Driven]** WHEN no AWS SDK imports are found, THE SDK_Analyzer SHALL return empty actions — not an error.

### REQ-IG-2: IaC Wildcard Detection

- **[Ubiquitous]** THE IaC_Scanner SHALL scan `*.tf`, `*.tf.json`, `*.yaml`, `*.yml`, `*.json`, `*.ts` files, excluding `vendor/`, `node_modules/`, `.git/`.
- **[Ubiquitous]** THE IaC_Scanner SHALL reject any individual file >5MB by logging a warning and skipping it — never fail the scan.
- **[Ubiquitous]** THE IaC_Scanner SHALL detect `"Action": "*"`, `Action = "*"`, `"Resource": "*"`, `Resource = "*"` in IAM statement contexts.
- **[Event-Driven]** WHEN a wildcard is found, THE IaC_Scanner SHALL record `IAMWildcard` with `risk: "critical"`.
- **[Unwanted]** IF a file cannot be read, THE IaC_Scanner SHALL skip it silently.

### REQ-IG-3: LLM Policy Generation (Async, Optional)

- **[Event-Driven]** WHEN the Handler has both an `LLMBackend` AND an `rpc.Notifier` AND actions are detected AND the request carries a client session ID (`rpc.ClientID` non-empty), THE Handler SHALL return actions + wildcards **immediately** and launch `startBackgroundPolicyGen()` in a detached goroutine.
- **[Ubiquitous]** THE initial response SHALL include a `request_id` for client-side correlation with the async notification.
- **[Ubiquitous]** THE background goroutine SHALL run on `h.baseCtx` re-tagged with the client ID via `rpc.WithClientID`, acquire a slot from `globalSem`, and enforce a 5-second per-call timeout.
- **[Ubiquitous]** THE LLM prompt SHALL include ONLY: the list of detected IAM actions and any wildcard statements. NOT raw source code or AST output.
- **[Ubiquitous]** THE system prompt SHALL request strict JSON output: `iam_policy_json` (valid IAM policy) and `aws_actions` (comma-separated). SHALL forbid `"Resource": "*"` unless the action inherently requires it.
- **[Event-Driven]** WHEN the LLM completes, THE Handler SHALL push a `notifications/message` notification with `PolicyEnrichment` payload via `notifier.Send()`.
- **[Unwanted]** IF the LLM errors or times out, THE Handler SHALL silently drop the notification — initial response was already delivered.
- **[Unwanted]** IF the `rpc.Notifier` is nil or `rpc.ClientID` is empty (e.g. stdio transport), THE Handler SHALL return actions + wildcards without enrichment — no goroutines launched.

### REQ-IG-4: MCP Tool Integration

- **[Ubiquitous]** THE Module SHALL expose `iamguard/analyze` accepting `directory_path` (required, string).
- **[Ubiquitous]** THE Handler SHALL register via `RegisterIAMGuard(dispatcher, handler)`.
- **[Ubiquitous]** THE Handler SHALL validate `directory_path` is non-empty → error `-32602` if missing.
- **[Ubiquitous]** THE response SHALL contain `actions`, `usages`, `wildcards`, `message`, and optionally `request_id`.

### REQ-IG-5: Read-Only Guarantee

- **[Ubiquitous]** THE Module SHALL NOT write, modify, or delete files. All operations are `os.ReadFile` + `go/parser`.
- **[Unwanted]** THE Module SHALL NOT initialize or invoke any AWS SDK clients.

### REQ-IG-6: Error Wrapping and Propagation

- **[Ubiquitous]** THE Module SHALL wrap all internal errors with `fmt.Errorf("context: %w", err)`.
- **[Ubiquitous]** Parse/validation errors → `-32602` (Invalid Params). Filesystem errors → `-32603` (Internal Error).
- **[Unwanted]** THE Module SHALL NOT use bare `errors.New` across the handler boundary.

## Acceptance Criteria

| ID | Trigger | Expected Result |
|----|---------|-----------------|
| ICA-1 | `.go` file calling `s3.GetObject` and `s3.PutObject` | 2 actions: `s3:GetObject`(count=1), `s3:PutObject`(count=1) |
| ICA-2 | IaC JSON with `"Action": "*"` | 1 wildcard, `risk="critical"` |
| ICA-3 | Terraform `.tf` with `Action = ["*"]` | 1 wildcard, `file_type="terraform"` |
| ICA-4 | `.go` with only stdlib imports | Empty actions, empty wildcards |
| ICA-5 | `directory_path=""` | Error `-32602` |
| ICA-6 | Nonexistent directory | Error `-32602` with path |
| ICA-7 | LLM + Notifier + session, 3 actions | Initial response has `request_id`; exactly 1 `PolicyEnrichment` notification with valid IAM policy JSON |
| ICA-8 | LLM returns error | Initial response delivered; zero notifications |
| ICA-9 | IaC file >5MB | File skipped, warning logged, scan continues |
| ICA-10 | Notifier is nil, actions present | Initial response without enrichment, no goroutines |
