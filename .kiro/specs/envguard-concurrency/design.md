# Design Document

## Overview

This design implements concurrent secret migration in the EnvGuard module using Go's `errgroup` for bounded worker pools and `golang.org/x/time/rate` for AWS API rate limiting. The core change replaces the sequential migration loop in `handler.go` with a parallel execution model that processes all findings concurrently while maintaining deterministic output ordering and per-finding error isolation.

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      EnvGuardHandler.Handle()                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Parse input                                                  │
│  2. scanner.Scan(diff)           ← sequential (CPU, µs)         │
│  3. ignore.Filter(findings)      ← sequential (in-memory)       │
│  4. migrateAll(ctx, findings)    ← NEW: concurrent migration    │
│  5. generateReplacements()       ← sequential (post-migration)  │
│  6. Return output                                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    migrateAll(ctx, findings)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  errgroup.Group (limit = WorkerCount)                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Worker 1 │  │ Worker 2 │  │ Worker 3 │  │ Worker N │       │
│  │ finding[0]│  │ finding[1]│  │ finding[2]│  │finding[N]│       │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘       │
│        │              │              │              │             │
│        ▼              ▼              ▼              ▼             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Rate Limiter (Wait)                          │    │
│  │         golang.org/x/time/rate.Limiter                   │    │
│  │         rate: 10 req/s, burst: 5                         │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                             │                                    │
│                             ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Migrator.Migrate(ctx, finding)               │    │
│  │         AWS Secrets Manager / SSM Parameter Store         │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Results written via index: findings[i].MigratedARN = arn       │
│                              findings[i].MigrationErr = err      │
└─────────────────────────────────────────────────────────────────┘
```

### Concurrency Model

The design uses `errgroup.Group` with `SetLimit(workerCount)` to bound concurrency. Each finding gets its own goroutine, but only `workerCount` goroutines execute simultaneously. Goroutines always return nil to errgroup so that one failure does not cancel siblings.

```go
g, gCtx := errgroup.WithContext(ctx)
g.SetLimit(workerCount)

for i := range findings {
    i := i
    g.Go(func() error {
        if err := limiter.Wait(gCtx); err != nil {
            findings[i].MigrationErr = err.Error()
            return nil
        }
        arn, err := migrator.Migrate(gCtx, findings[i])
        if err != nil {
            findings[i].MigrationErr = err.Error()
        } else {
            findings[i].MigratedARN = arn
        }
        return nil
    })
}
g.Wait()
```

Key design decisions:
- **Always return nil from goroutines**: Independent error handling per finding. Prevents errgroup from cancelling the group context on error.
- **Index-based writes**: Each goroutine writes only to `findings[i]` — no shared append, no mutex needed.
- **Rate limiter shared across workers**: A single `rate.Limiter` instance ensures global rate compliance.

## Components and Interfaces

### EnvGuardHandler (modified)

```go
// EnvGuardHandler orchestrates scan → filter → migrate → respond.
type EnvGuardHandler struct {
    scanner     *SecretScanner
    ignore      *IgnoreParser    // may be nil
    migrator    *Migrator        // may be nil
    workerCount int              // max concurrent migration goroutines
    limiter     *rate.Limiter    // shared rate limiter for AWS API calls
}

// NewEnvGuardHandler creates a handler with concurrency configuration.
func NewEnvGuardHandler(
    scanner *SecretScanner,
    ignore *IgnoreParser,
    migrator *Migrator,
    workerCount int,
    limiter *rate.Limiter,
) *EnvGuardHandler
```

### migrateAll (new private method)

```go
// migrateAll executes all migrations concurrently using a bounded worker pool.
// Each finding is processed independently; errors are recorded per-finding.
// The method blocks until all goroutines complete.
func (h *EnvGuardHandler) migrateAll(ctx context.Context, findings []SecretFinding)
```

### EnvGuardConfig (modified)

```go
type EnvGuardConfig struct {
    IgnoreFile      string  `yaml:"ignore_file"`
    MigrationTarget string  `yaml:"migration_target"`
    SSMPrefix       string  `yaml:"ssm_prefix"`
    WorkerCount     int     `yaml:"worker_count"`  // max concurrent workers (default: 5)
    RateLimit       float64 `yaml:"rate_limit"`    // AWS API calls/sec (default: 10.0)
    RateBurst       int     `yaml:"rate_burst"`    // burst size (default: 5)
}
```

### External Interfaces Used

| Interface | Package | Usage |
|-----------|---------|-------|
| `errgroup.Group` | `golang.org/x/sync/errgroup` | Bounded goroutine pool with context cancellation |
| `rate.Limiter` | `golang.org/x/time/rate` | Token-bucket rate limiter for AWS API throttle protection |
| `SecretsManagerClient` | `internal/envguard` | Existing interface for AWS Secrets Manager (unchanged) |
| `SSMClient` | `internal/envguard` | Existing interface for AWS SSM Parameter Store (unchanged) |

## Data Models

### SecretFinding (unchanged)

```go
type SecretFinding struct {
    LineNumber   int    `json:"line_number"`
    FilePath     string `json:"file_path"`
    SecretType   string `json:"secret_type"`
    SecretValue  string `json:"secret_value,omitempty"`
    Replacement  string `json:"replacement,omitempty"`
    MigratedARN  string `json:"migrated_arn,omitempty"`
    MigrationErr string `json:"migration_error,omitempty"`
}
```

Fields written concurrently (one goroutine per index):
- `MigratedARN`: Set on successful migration
- `MigrationErr`: Set on failed migration or rate limit timeout
- `Replacement`: Set sequentially after all migrations complete

### EnvGuardInput (unchanged)

```go
type EnvGuardInput struct {
    Diff     string `json:"diff"`
    FilePath string `json:"file_path,omitempty"`
}
```

### EnvGuardOutput (unchanged)

```go
type EnvGuardOutput struct {
    Blocked  bool            `json:"blocked"`
    Findings []SecretFinding `json:"findings"`
    Message  string          `json:"message"`
}
```

### Configuration Fields (new)

| Field | Type | Default | YAML key | Description |
|-------|------|---------|----------|-------------|
| WorkerCount | int | 5 | `envguard.worker_count` | Max concurrent migration goroutines |
| RateLimit | float64 | 10.0 | `envguard.rate_limit` | AWS API calls per second |
| RateBurst | int | 5 | `envguard.rate_burst` | Burst tokens for rate limiter |

## Data Flow

```
Input (diff string)
    │
    ▼
Scanner.Scan(diff) → []SecretFinding (sequential, µs)
    │
    ▼
IgnoreParser.Filter(findings) → []SecretFinding (sequential, in-memory)
    │
    ▼
migrateAll(ctx, findings) — concurrent worker pool
    │
    ├── goroutine[0]: limiter.Wait() → Migrate(finding[0]) → findings[0].ARN/Err
    ├── goroutine[1]: limiter.Wait() → Migrate(finding[1]) → findings[1].ARN/Err
    └── goroutine[N]: limiter.Wait() → Migrate(finding[N]) → findings[N].ARN/Err
    │
    ▼
g.Wait() — all goroutines complete
    │
    ▼
Generate replacements (sequential, post-migration)
    │
    ▼
Return EnvGuardOutput
```

## Correctness Properties

### Property 1: No data races

**Validates: Requirements 5.1, 5.2**

Each goroutine writes exclusively to its own index `findings[i]`. The Go memory model guarantees that writes to distinct elements of a slice do not race. Verified by `go test -race`.

### Property 2: Deterministic output order

**Validates: Requirements 5.3**

The findings slice maintains its original ordering. Goroutines write to pre-assigned indices; the output order is independent of completion order.

### Property 3: Bounded concurrency

**Validates: Requirements 1.2, 1.3**

`errgroup.SetLimit(workerCount)` guarantees at most `workerCount` goroutines execute simultaneously. This is enforced by errgroup's internal semaphore.

### Property 4: Rate limit compliance

**Validates: Requirements 2.1, 2.2**

All workers share a single `rate.Limiter`. The `Wait()` call blocks until a token is available, ensuring the aggregate request rate never exceeds the configured limit.

### Property 5: No goroutine leaks

**Validates: Requirements 4.1, 6.1**

`g.Wait()` blocks until every goroutine launched via `g.Go()` returns. Since goroutines always return nil (never error), all goroutines complete regardless of individual migration outcomes.

### Property 6: Context propagation

**Validates: Requirements 4.1, 4.2, 2.3**

`errgroup.WithContext(ctx)` derives a child context (`gCtx`). If the parent context is cancelled, `limiter.Wait(gCtx)` and `migrator.Migrate(gCtx, ...)` both observe the cancellation and return immediately with a context error.

### Property 7: Partial results on cancellation

**Validates: Requirements 4.3, 6.3**

When context is cancelled, goroutines that already completed have their results persisted in the findings slice. Goroutines that were waiting record a context cancellation error in `MigrationErr`.

## Error Handling

### Per-Finding Errors

| Error Source | Handling | Field Set |
|--------------|----------|-----------|
| Rate limiter context cancelled | Record `err.Error()` | `findings[i].MigrationErr` |
| AWS Secrets Manager API error | Record `err.Error()` | `findings[i].MigrationErr` |
| AWS SSM PutParameter error | Record `err.Error()` | `findings[i].MigrationErr` |
| Migration timeout (10s per call) | Record `context.DeadlineExceeded` | `findings[i].MigrationErr` |
| Successful migration | Set ARN | `findings[i].MigratedARN` |

### Error Isolation Strategy

- Individual migration failures do NOT propagate to errgroup (goroutines return nil)
- Individual failures do NOT cancel sibling goroutines
- Individual failures do NOT prevent the handler from returning a complete response
- The handler always returns `EnvGuardOutput` with all findings, each annotated with success or failure

### Handler-Level Errors

| Condition | Response |
|-----------|----------|
| Invalid JSON params | Return JSON-RPC invalid params error (-32602) |
| Empty diff | Return success with `blocked: false`, empty findings |
| No migrator configured | Skip migration entirely, return findings without ARN |
| All migrations fail | Return `blocked: true` with all `MigrationErr` fields populated |

### Configuration Validation Errors

| Condition | Error Message |
|-----------|---------------|
| `worker_count < 1` | `"envguard.worker_count: must be greater than 0"` |
| `rate_limit <= 0` | `"envguard.rate_limit: must be greater than 0"` |
| `rate_burst < 1` | `"envguard.rate_burst: must be greater than 0"` |

## Changes Required

### File: `internal/config/config.go`

Add `WorkerCount`, `RateLimit`, `RateBurst` fields to `EnvGuardConfig`. Add validation rules in `validate()`.

### File: `internal/config/defaults.go`

Set defaults: `WorkerCount: 5`, `RateLimit: 10.0`, `RateBurst: 5`.

### File: `internal/envguard/handler.go`

- Add `workerCount int` and `limiter *rate.Limiter` fields to struct
- Update `NewEnvGuardHandler` signature
- Replace sequential migration loop with `migrateAll` method
- Add imports: `golang.org/x/sync/errgroup`, `golang.org/x/time/rate`

### File: `main.go`

- Create `rate.Limiter` from config
- Pass `workerCount` and `limiter` to `NewEnvGuardHandler`

## New Dependencies

| Package | Purpose | Import path |
|---------|---------|-------------|
| errgroup | Bounded concurrent goroutine management | `golang.org/x/sync/errgroup` |
| rate | Token-bucket rate limiter | `golang.org/x/time/rate` |

## Testing Strategy

### Unit Tests

1. **TestMigrateAll_Concurrent**: Multiple findings migrated in parallel (assert total time < N × delay)
2. **TestMigrateAll_WorkerCountBounds**: Max concurrent goroutines bounded by WorkerCount (atomic counter)
3. **TestMigrateAll_RateLimiting**: Rate limiter respected (measure inter-call timing)
4. **TestMigrateAll_ContextCancellation**: Partial results on cancelled context, no goroutine leaks
5. **TestMigrateAll_IndependentErrors**: One failure doesn't block others
6. **TestMigrateAll_AllFail**: All errors populated, complete slice returned
7. **TestMigrateAll_OrderPreserved**: Output order matches input order
8. **TestMigrateAll_SingleWorker**: WorkerCount=1 behaves sequentially

### Existing Test Compatibility

Update existing tests to pass `workerCount` and `limiter` to constructor. Use `rate.NewLimiter(rate.Inf, 0)` for unlimited rate in legacy tests.

## Performance Characteristics

| Scenario | Before (sequential) | After (concurrent, 5 workers) |
|----------|--------------------|-----------------------------|
| 1 secret | ~10s worst case | ~10s (same) |
| 5 secrets | ~50s worst case | ~10s (parallel) |
| 10 secrets | ~100s worst case | ~20s (2 batches) |
| 20 secrets | ~200s worst case | ~40s (4 batches) |

## Backward Compatibility

- `NewEnvGuardHandler` signature changes — internal package, no external consumers
- `EnvGuardOutput` struct: unchanged
- `SecretFinding` struct: unchanged
- `RegisterEnvGuard` signature: unchanged
- Wire protocol (JSON-RPC input/output): unchanged
