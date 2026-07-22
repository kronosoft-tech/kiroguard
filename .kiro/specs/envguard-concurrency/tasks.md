# Implementation Plan

## Overview

This plan implements concurrent secret migration in the EnvGuard module. Tasks are ordered by dependency: config changes first, then handler modifications, then main.go wiring, and finally tests and verification.

## Tasks

- [x] 1. Add new dependencies
  Requirements: 1, 2
  File(s): go.mod, go.sum
  Run `go get golang.org/x/sync/errgroup golang.org/x/time/rate` to add the errgroup and rate limiter packages required for concurrent migration and API throttling.

- [x] 2. Add concurrency config fields
  Requirements: 3, 2
  File(s): internal/config/config.go
  Add `WorkerCount int`, `RateLimit float64`, and `RateBurst int` fields with YAML tags `worker_count`, `rate_limit`, and `rate_burst` to the `EnvGuardConfig` struct.

- [x] 3. Update config defaults
  Requirements: 3
  File(s): internal/config/defaults.go
  Set default values in the `Default()` function: `WorkerCount: 5`, `RateLimit: 10.0`, `RateBurst: 5`.

- [x] 4. Add config validation
  Requirements: 3
  File(s): internal/config/config.go
  Add validation rules in the `validate()` function: WorkerCount must be >= 1, RateLimit must be > 0, RateBurst must be >= 1. Return descriptive error messages matching the format `"envguard.worker_count: must be greater than 0"`.

- [x] 5. Update EnvGuardHandler struct and constructor
  Requirements: 1, 2, 5
  File(s): internal/envguard/handler.go
  Add `workerCount int` and `limiter *rate.Limiter` fields to `EnvGuardHandler`. Update `NewEnvGuardHandler` to accept `workerCount int` and `limiter *rate.Limiter` as additional parameters and store them in the struct.

- [x] 6. Implement migrateAll method
  Requirements: 1, 2, 4, 5, 6
  File(s): internal/envguard/handler.go
  Create a private `migrateAll(ctx context.Context, findings []SecretFinding)` method that uses `errgroup.Group` with `SetLimit(h.workerCount)`. Each goroutine calls `h.limiter.Wait(gCtx)` before migrating. Goroutines write results via index-based assignment and always return nil to prevent group cancellation. Import `golang.org/x/sync/errgroup` and `golang.org/x/time/rate`.

- [x] 7. Replace sequential loop with migrateAll
  Requirements: 1, 6, 7
  File(s): internal/envguard/handler.go
  Replace the sequential `for i := range findings` migration loop in `Handle()` with a call to `h.migrateAll(ctx, findings)`. Keep the replacement generation loop sequential after migrateAll returns. Only call migrateAll when `h.migrator != nil`.

- [x] 8. Update main.go wiring
  Requirements: 2, 3
  File(s): main.go
  Import `golang.org/x/time/rate`. Create a `rate.Limiter` using `rate.NewLimiter(rate.Limit(cfg.EnvGuard.RateLimit), cfg.EnvGuard.RateBurst)`. Pass `cfg.EnvGuard.WorkerCount` and the limiter to `NewEnvGuardHandler`.

- [x] 9. Update existing handler tests
  Requirements: 7
  File(s): internal/envguard/handler_test.go
  Update all existing calls to `NewEnvGuardHandler` in tests to pass the new `workerCount` and `limiter` parameters. Use `workerCount: 5` and `rate.NewLimiter(rate.Inf, 0)` for unlimited rate in legacy tests to maintain existing behavior.

- [x] 10. Add concurrency unit tests
  Requirements: 1, 2, 4, 5, 6
  File(s): internal/envguard/handler_test.go
  Add tests: (1) concurrent migration executes in parallel (total time < N × per-migration delay), (2) max concurrent goroutines bounded by WorkerCount (atomic counter), (3) rate limiter is respected (measure timing), (4) context cancellation returns partial results with no goroutine leaks, (5) one migration failure does not block others, (6) output order matches input order regardless of completion order.

- [x] 11. Add config validation tests
  Requirements: 3
  File(s): internal/config/config_test.go
  Add tests verifying: WorkerCount < 1 triggers validation error, RateLimit <= 0 triggers validation error, RateBurst < 1 triggers validation error, and valid values pass validation.

- [x] 12. Run race detector
  Requirements: 5
  File(s): (command only)
  Execute `go test -race ./internal/envguard/...` to verify no data races exist in the concurrent migration implementation.

- [x] 13. Run full test suite
  Requirements: 7
  File(s): (command only)
  Execute `go test ./...` to verify no regressions across the entire codebase.

## Task Dependency Graph

```json
{
  "waves": [
    {
      "wave": 1,
      "tasks": [1],
      "description": "Add golang.org/x dependencies"
    },
    {
      "wave": 2,
      "tasks": [2, 3, 5],
      "description": "Config fields, defaults, and handler struct changes (parallel)"
    },
    {
      "wave": 3,
      "tasks": [4, 6],
      "description": "Config validation and migrateAll implementation (parallel)"
    },
    {
      "wave": 4,
      "tasks": [7, 8],
      "description": "Replace sequential loop and update main.go wiring"
    },
    {
      "wave": 5,
      "tasks": [9, 10, 11],
      "description": "Update existing tests, add concurrency tests, add config tests (parallel)"
    },
    {
      "wave": 6,
      "tasks": [12, 13],
      "description": "Run race detector and full test suite verification"
    }
  ]
}
```

## Notes

- Tasks 2, 3, 4 (config) are independent of Tasks 5, 6, 7 (handler) and can be done in parallel.
- Task 8 (main.go) depends on both config and handler changes being complete.
- Tasks 9, 10, 11 (tests) depend on Tasks 5-8 being complete.
- Tasks 12, 13 (verification) are final gates and depend on all code + tests being written.
- Use `rate.NewLimiter(rate.Inf, 0)` in existing tests to avoid changing their behavior.
- The `golang.org/x/sync/errgroup` and `golang.org/x/time/rate` packages are official Go extended libraries.
