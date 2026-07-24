# Requirements Document

## Introduction

This feature adds concurrency to the EnvGuard module's secret migration phase. Currently, when the handler detects N secrets in a diff, it migrates them sequentially to AWS Secrets Manager or SSM Parameter Store, each with a 10-second timeout — resulting in N × 10s worst case latency. This feature introduces parallel migration using an errgroup worker pool with rate limiting, configurable worker count, and graceful context cancellation while maintaining race-condition safety.

## Glossary

- **Handler**: The `EnvGuardHandler` struct that orchestrates the scan flow (scan → filter → migrate → respond)
- **Migrator**: The `Migrator` struct responsible for storing secrets in AWS Secrets Manager or SSM Parameter Store
- **Findings_Slice**: The `[]SecretFinding` slice holding all detected secrets for a given scan request
- **Worker_Pool**: A bounded set of concurrent goroutines executing migrations via `errgroup.Group`
- **Rate_Limiter**: A `golang.org/x/time/rate.Limiter` instance that throttles AWS API calls to prevent throttling
- **Worker_Count**: The maximum number of concurrent migration goroutines, configured via `EnvGuardConfig`
- **Errgroup**: The `golang.org/x/sync/errgroup.Group` type used to manage concurrent goroutines with shared error propagation and context cancellation

## Requirements

### Requirement 1: Concurrent Migration Execution

**User Story:** As a developer committing code with multiple secrets, I want all secret migrations to run in parallel, so that the total migration time is bounded by the slowest single migration rather than the sum of all migrations.

#### Acceptance Criteria

1. WHEN the Handler detects multiple secrets requiring migration, THE Worker_Pool SHALL execute all migrations concurrently rather than sequentially
2. THE Worker_Pool SHALL limit the number of concurrent migration goroutines to the configured Worker_Count value
3. WHEN Worker_Count is set to 1, THE Worker_Pool SHALL execute migrations sequentially (single worker behavior)

### Requirement 2: Rate Limiting

**User Story:** As a system operator, I want AWS API calls to be rate-limited during concurrent migrations, so that the system does not trigger AWS API throttling.

#### Acceptance Criteria

1. THE Rate_Limiter SHALL restrict the rate of AWS API calls across all concurrent workers
2. WHEN a worker is ready to migrate but the Rate_Limiter denies the request, THE worker SHALL wait until a token becomes available or the context is cancelled
3. IF the context is cancelled while a worker waits for a rate limit token, THEN THE worker SHALL abort without making the AWS API call

### Requirement 3: Configurable Worker Count

**User Story:** As a system operator, I want to configure the maximum number of concurrent migration workers, so that I can tune concurrency to match my AWS API quota and system resources.

#### Acceptance Criteria

1. THE EnvGuardConfig SHALL include a WorkerCount field specifying the maximum number of concurrent migration goroutines
2. WHEN WorkerCount is not specified in the configuration file, THE system SHALL default to 5 workers
3. WHEN WorkerCount is set to a value less than 1, THE system SHALL reject the configuration with a descriptive validation error

### Requirement 4: Context Cancellation and Graceful Shutdown

**User Story:** As a system operator, I want all in-flight migrations to be cancelled gracefully when the parent context is cancelled, so that resources are released promptly without orphaned goroutines.

#### Acceptance Criteria

1. WHEN the parent context is cancelled, THE Worker_Pool SHALL cancel all in-flight migration goroutines
2. WHEN a migration goroutine receives a cancellation signal, THE Migrator SHALL stop waiting for the AWS response and return a context error
3. WHEN the parent context is cancelled, THE Handler SHALL return partial results for any migrations that completed before cancellation

### Requirement 5: Race Condition Safety

**User Story:** As a developer, I want the concurrent migration results to be written safely to the findings slice, so that no data races corrupt the output.

#### Acceptance Criteria

1. THE Worker_Pool SHALL use index-based assignment on the Findings_Slice to write migration results, not append operations
2. WHEN multiple workers write migration results concurrently, THE Handler SHALL ensure each worker writes only to its own designated index in the Findings_Slice
3. THE Findings_Slice SHALL maintain the same ordering of findings regardless of which migrations complete first

### Requirement 6: Independent Error Handling

**User Story:** As a developer, I want individual migration failures to be recorded per-finding without blocking other migrations, so that successful migrations are preserved even when some fail.

#### Acceptance Criteria

1. WHEN a single migration fails, THE Worker_Pool SHALL continue executing remaining migrations without interruption
2. WHEN a migration fails, THE Handler SHALL record the error message in the corresponding finding's MigrationErr field
3. WHEN all migrations complete (success or failure), THE Handler SHALL return the complete Findings_Slice with per-finding error details
4. IF all migrations fail, THEN THE Handler SHALL still return the complete Findings_Slice with all error details populated

### Requirement 7: Module Independence

**User Story:** As a maintainer, I want the concurrency changes to be fully contained within the EnvGuard module, so that other modules remain unaffected and the system stays modular.

#### Acceptance Criteria

1. THE concurrency implementation SHALL modify only files within `internal/envguard/` and `internal/config/`
2. THE Handler SHALL not introduce any imports from or dependencies on other KiroGuard modules (vulnscanner, cleanarch, finops)
3. WHEN the EnvGuard module is modified, THE existing public API (function signatures, types, and registration) SHALL remain backward compatible
