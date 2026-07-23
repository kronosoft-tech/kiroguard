package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/time/rate"

	"github.com/luiferdev/kiroguard/internal/cleanarch"
	"github.com/luiferdev/kiroguard/internal/envguard"
	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// buildIntegratedDispatcher wires the Env-Guard and Clean-Arch modules onto a
// single dispatcher, mirroring the composition performed in main(). It uses the
// heuristic LLM backend so the test needs no AWS credentials.
func buildIntegratedDispatcher() *rpc.Dispatcher {
	d := rpc.NewDispatcher()

	heuristic := llm.NewHeuristicProvider()

	arch := cleanarch.NewCleanArchHandler(nil, heuristic)
	cleanarch.RegisterCleanArch(d, arch)

	scanner := envguard.NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(10), 5)
	env := envguard.NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
	envguard.RegisterEnvGuard(d, env)

	return d
}

func dispatch(t *testing.T, d *rpc.Dispatcher, method string, params any) *rpc.Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	id := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &id, Method: method, Params: raw}
	return d.Dispatch(context.Background(), req)
}

// TestIntegration_EnvGuardAndCleanArchCoexist verifies that both modules can be
// registered on the same dispatcher and each responds correctly, with no route
// collision — the essence of running the two modules together.
func TestIntegration_EnvGuardAndCleanArchCoexist(t *testing.T) {
	d := buildIntegratedDispatcher()

	// --- Clean-Arch: a domain package importing infrastructure is a violation. ---
	tmp := t.TempDir()
	domainDir := filepath.Join(tmp, "domain")
	if err := os.MkdirAll(domainDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := "package domain\n\nimport \"github.com/myapp/infrastructure/database\"\n\nvar _ = database.Connect\n"
	if err := os.WriteFile(filepath.Join(domainDir, "service.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	archResp := dispatch(t, d, "cleanarch/analyze", cleanarch.CleanArchInput{DirectoryPath: tmp})
	if archResp.Error != nil {
		t.Fatalf("cleanarch/analyze error: %+v", archResp.Error)
	}
	var archOut cleanarch.CleanArchOutput
	if err := json.Unmarshal(archResp.Result, &archOut); err != nil {
		t.Fatalf("decode cleanarch result: %v", err)
	}
	if len(archOut.Violations) != 1 {
		t.Errorf("expected 1 architecture violation, got %d", len(archOut.Violations))
	}

	// --- Env-Guard: a diff adding an AWS access key must be blocked. ---
	diff := "+\tapiKey := \"AKIAIOSFODNN7EXAMPLE\"\n"
	envResp := dispatch(t, d, "envguard/scan", envguard.EnvGuardInput{Diff: diff, FilePath: "config.go"})
	if envResp.Error != nil {
		t.Fatalf("envguard/scan error: %+v", envResp.Error)
	}
	var envOut envguard.EnvGuardOutput
	if err := json.Unmarshal(envResp.Result, &envOut); err != nil {
		t.Fatalf("decode envguard result: %v", err)
	}
	if !envOut.Blocked {
		t.Errorf("expected envguard to block the diff containing a secret, got %+v", envOut)
	}

	// --- Routing isolation: an unknown method must not resolve to either module. ---
	unknown := dispatch(t, d, "does/not-exist", map[string]string{})
	if unknown.Error == nil || unknown.Error.Code != rpc.CodeMethodNotFound {
		t.Errorf("expected MethodNotFound for unknown method, got %+v", unknown.Error)
	}
}
