package envguard

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/time/rate"
)

func TestEnvGuard_EmitsStructuredScanLogsWithRedaction(t *testing.T) {
	var buf bytes.Buffer
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	h := NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
	h.logger = slog.New(slog.NewJSONHandler(&buf, nil))

	const secret = "AKIAIOSFODNN7EXAMPLE"
	diff := "+\tapiKey := \"" + secret + "\"\n"
	params, _ := json.Marshal(EnvGuardInput{Diff: diff, FilePath: "config.go"})

	if _, err := h.Handle(context.Background(), params); err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"event":"scan_started"`) {
		t.Errorf("expected scan_started event, got: %s", out)
	}
	if !strings.Contains(out, `"event":"scan_completed"`) {
		t.Errorf("expected scan_completed event, got: %s", out)
	}

	// Redaction: the raw secret value must NEVER appear in the logs.
	if strings.Contains(out, secret) {
		t.Errorf("SECURITY: secret value leaked into logs:\n%s", out)
	}

	// The completed event should report the count of detected secrets.
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["event"] == "scan_completed" {
			found = true
			if v, ok := rec["secrets_found"].(float64); !ok || v < 1 {
				t.Errorf("scan_completed secrets_found = %v, want >= 1", rec["secrets_found"])
			}
		}
	}
	if !found {
		t.Error("no scan_completed record parsed")
	}
}
