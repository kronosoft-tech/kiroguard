package envguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/time/rate"
)

// failingSMClient is a hand-written mock whose CreateSecret always fails.
type failingSMClient struct{}

func (failingSMClient) CreateSecret(_ context.Context, _ *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	return nil, errors.New("AccessDeniedException: not authorized")
}

func TestEnvGuard_LogsMigrationFailureRedacted(t *testing.T) {
	var buf bytes.Buffer
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	migrator := NewMigratorWithClients(
		MigratorConfig{Target: "secrets_manager", Region: "us-east-1"},
		failingSMClient{}, nil,
	)
	h := NewEnvGuardHandler(scanner, nil, migrator, 5, limiter)
	h.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	const secret = "AKIAIOSFODNN7EXAMPLE"
	diff := "+\tkey := \"" + secret + "\"\n"
	params, _ := json.Marshal(EnvGuardInput{Diff: diff, FilePath: "config.go"})

	if _, err := h.Handle(context.Background(), params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"event":"migration_failed"`) {
		t.Errorf("expected migration_failed event, got: %s", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("SECURITY: secret value leaked into migration logs:\n%s", out)
	}
}
