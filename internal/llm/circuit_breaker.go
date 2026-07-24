package llm

import (
	"context"
	"errors"
	"sync"
	"time"
)

// CircuitState represents the current state of the Circuit Breaker.
type CircuitState string

const (
	StateClosed   CircuitState = "CLOSED"    // Normal operation: requests pass through to primary
	StateOpen     CircuitState = "OPEN"      // Bedrock is down: requests fail fast to fallback in 0ms
	StateHalfOpen CircuitState = "HALF_OPEN" // Cooldown elapsed: probing primary with 1 test request
)

const (
	defaultFailureThreshold = 3
	defaultCooldownPeriod   = 30 * time.Second
)

// ErrCircuitOpen is returned when a request is rejected because the circuit is OPEN.
var ErrCircuitOpen = errors.New("circuit breaker is OPEN: primary LLM backend is unavailable")

// CircuitBreakerStats provides real-time metrics for monitoring.
type CircuitBreakerStats struct {
	State           CircuitState `json:"state"`
	Failures        int          `json:"consecutive_failures"`
	Successes       int          `json:"consecutive_successes"`
	TotalRejected   int64        `json:"total_rejected"`
	LastStateChange time.Time    `json:"last_state_change"`
}

// CircuitBreakerLLM wraps a primary LLMBackend and fallback LLMBackend with a thread-safe
// Circuit Breaker pattern. If the primary backend fails failureThreshold consecutive times,
// the circuit OPENS and all subsequent calls fail fast to fallback in 0ms for cooldownPeriod,
// preventing network latency and CPU waste during AWS regional outages.
type CircuitBreakerLLM struct {
	primary   LLMBackend
	fallback  LLMBackend
	threshold int
	cooldown  time.Duration

	mu              sync.Mutex
	state           CircuitState
	failures        int
	successes       int
	totalRejected   int64
	lastStateChange time.Time
}

// NewCircuitBreakerLLM constructs a Circuit Breaker around a primary and fallback LLMBackend.
func NewCircuitBreakerLLM(primary, fallback LLMBackend, threshold int, cooldown time.Duration) *CircuitBreakerLLM {
	if threshold <= 0 {
		threshold = defaultFailureThreshold
	}
	if cooldown <= 0 {
		cooldown = defaultCooldownPeriod
	}
	return &CircuitBreakerLLM{
		primary:         primary,
		fallback:        fallback,
		threshold:       threshold,
		cooldown:        cooldown,
		state:           StateClosed,
		lastStateChange: time.Now(),
	}
}

// Complete satisfies the LLMBackend interface.
func (cb *CircuitBreakerLLM) Complete(ctx context.Context, p Prompt) (*LLMResponse, error) {
	state := cb.currentState()

	if state == StateOpen {
		// Circuit is OPEN: Fail fast in 0ms to fallback
		cb.mu.Lock()
		cb.totalRejected++
		cb.mu.Unlock()

		return cb.invokeFallback(ctx, p, "circuit_open")
	}

	// State is CLOSED or HALF_OPEN: invoke primary backend
	resp, err := cb.primary.Complete(ctx, p)
	if err != nil {
		cb.onFailure()
		return cb.invokeFallback(ctx, p, "primary_error")
	}

	cb.onSuccess()
	return resp, nil
}

// invokeFallback calls the fallback backend and marks metadata["circuit_breaker"] = reason.
func (cb *CircuitBreakerLLM) invokeFallback(ctx context.Context, p Prompt, reason string) (*LLMResponse, error) {
	if cb.fallback == nil {
		return nil, ErrCircuitOpen
	}
	resp, err := cb.fallback.Complete(ctx, p)
	if err != nil {
		return nil, err
	}
	if resp.Metadata == nil {
		resp.Metadata = make(map[string]string)
	}
	resp.Metadata["circuit_breaker"] = reason
	return resp, nil
}

// currentState evaluates and returns the current CircuitState under lock, transitioning
// from OPEN to HALF_OPEN if cooldown has elapsed.
func (cb *CircuitBreakerLLM) currentState() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen {
		if time.Since(cb.lastStateChange) >= cb.cooldown {
			cb.state = StateHalfOpen
			cb.lastStateChange = time.Now()
		}
	}
	return cb.state
}

// onSuccess records a successful primary call and updates state under lock.
func (cb *CircuitBreakerLLM) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		cb.state = StateClosed
		cb.failures = 0
		cb.lastStateChange = time.Now()
	case StateClosed:
		cb.failures = 0
	}
	cb.successes++
}

// onFailure records a primary failure and opens the circuit if threshold is reached.
func (cb *CircuitBreakerLLM) onFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.successes = 0

	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.threshold {
			cb.state = StateOpen
			cb.lastStateChange = time.Now()
		}
	case StateHalfOpen:
		cb.state = StateOpen
		cb.lastStateChange = time.Now()
	}
}

// Stats returns a point-in-time snapshot of the Circuit Breaker metrics.
func (cb *CircuitBreakerLLM) Stats() CircuitBreakerStats {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return CircuitBreakerStats{
		State:           cb.state,
		Failures:        cb.failures,
		Successes:       cb.successes,
		TotalRejected:   cb.totalRejected,
		LastStateChange: cb.lastStateChange,
	}
}
