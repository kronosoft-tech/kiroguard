package envguard

import (
	"context"
	"encoding/json"
	"testing"

	"golang.org/x/time/rate"
)

func TestEnvGuard_MetricsSnapshot(t *testing.T) {
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	h := NewEnvGuardHandler(scanner, nil, nil, 5, limiter)

	const secret = "AKIAIOSFODNN7EXAMPLE"
	diff := "+\tkey := \"" + secret + "\"\n"
	params, _ := json.Marshal(EnvGuardInput{Diff: diff, FilePath: "config.go"})

	if _, err := h.Handle(context.Background(), params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	m := h.MetricsSnapshot()
	if m.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", m.ScansTotal)
	}
	if m.SecretsDetectedTotal < 1 {
		t.Errorf("SecretsDetectedTotal = %d, want >= 1", m.SecretsDetectedTotal)
	}
	if m.BlockedTotal != 1 {
		t.Errorf("BlockedTotal = %d, want 1", m.BlockedTotal)
	}
}
