package envguard

import (
	"context"
	"encoding/json"
	"testing"

	"golang.org/x/time/rate"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

func newTestHandler() *EnvGuardHandler {
	scanner := NewSecretScanner()
	limiter := rate.NewLimiter(rate.Limit(100), 10)
	return NewEnvGuardHandler(scanner, nil, nil, 5, limiter)
}

func TestEnvGuard_MalformedParamsReturnsInvalidParams(t *testing.T) {
	d := rpc.NewDispatcher()
	RegisterEnvGuard(d, newTestHandler())

	id := json.RawMessage(`1`)
	req := &rpc.Request{JSONRPC: "2.0", ID: &id, Method: "envguard/scan", Params: json.RawMessage(`{invalid json`)}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if resp.Error.Code != rpc.CodeInvalidParams {
		t.Errorf("error code = %d, want %d (Invalid Params)", resp.Error.Code, rpc.CodeInvalidParams)
	}
}
