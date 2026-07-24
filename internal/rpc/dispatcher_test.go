package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestDispatch_Success(t *testing.T) {
	d := NewDispatcher()
	d.Register("echo", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return map[string]string{"echo": string(params)}, nil
	})

	id := json.RawMessage(`1`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "echo",
		Params:  json.RawMessage(`"hello"`),
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if result["echo"] != `"hello"` {
		t.Errorf("unexpected echo value: %q", result["echo"])
	}
}

func TestDispatch_MethodNotFound(t *testing.T) {
	d := NewDispatcher()

	id := json.RawMessage(`2`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "nonexistent",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != CodeMethodNotFound {
		t.Errorf("expected code %d, got %d", CodeMethodNotFound, resp.Error.Code)
	}
}

func TestDispatch_HandlerError(t *testing.T) {
	d := NewDispatcher()
	d.Register("fail", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return nil, errors.New("something went wrong")
	})

	id := json.RawMessage(`3`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "fail",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != CodeInternalError {
		t.Errorf("expected code %d, got %d", CodeInternalError, resp.Error.Code)
	}
	if resp.Error.Message == "" {
		t.Error("expected non-empty error message")
	}
}

func TestDispatch_PanicRecovery(t *testing.T) {
	d := NewDispatcher()
	d.Register("panic", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		panic("unexpected failure")
	})

	id := json.RawMessage(`4`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "panic",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response after panic")
	}
	if resp.Error.Code != CodeInternalError {
		t.Errorf("expected code %d, got %d", CodeInternalError, resp.Error.Code)
	}
	if resp.Error.Message == "" {
		t.Error("expected non-empty error message describing panic")
	}
}

func TestDispatch_ConcurrentSafety(t *testing.T) {
	d := NewDispatcher()
	d.Register("counter", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return map[string]string{"ok": "true"}, nil
	})

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			id := json.RawMessage(`99`)
			req := &Request{
				JSONRPC: "2.0",
				ID:      &id,
				Method:  "counter",
			}
			resp := d.Dispatch(context.Background(), req)
			if resp.Error != nil {
				t.Errorf("unexpected error in concurrent dispatch: %v", resp.Error)
			}
		}()
	}

	wg.Wait()
}

func TestDispatch_ConcurrentRegisterAndDispatch(t *testing.T) {
	d := NewDispatcher()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines register handlers
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			method := "method"
			d.Register(method, func(ctx context.Context, params json.RawMessage) (interface{}, error) {
				return n, nil
			})
		}(i)
	}

	// Other half dispatches
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			id := json.RawMessage(`1`)
			req := &Request{
				JSONRPC: "2.0",
				ID:      &id,
				Method:  "method",
			}
			// Result can be either success or method-not-found depending on timing
			d.Dispatch(context.Background(), req)
		}()
	}

	wg.Wait()
}

func TestDispatch_NilID(t *testing.T) {
	d := NewDispatcher()
	d.Register("notify", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return "ok", nil
	})

	req := &Request{
		JSONRPC: "2.0",
		ID:      nil,
		Method:  "notify",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}
	if resp.ID != nil {
		t.Error("expected nil ID in response for notification")
	}
}

func TestDispatch_ValidationErrorMapsToInvalidParams(t *testing.T) {
	d := NewDispatcher()
	d.Register("validate", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return nil, NewValidationError("directory_path is required")
	})

	id := json.RawMessage(`5`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "validate",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("expected code %d (Invalid Params), got %d", CodeInvalidParams, resp.Error.Code)
	}
	if resp.Error.Message == "" {
		t.Error("expected non-empty error message")
	}
}

func TestDispatch_WrappedValidationErrorMapsToInvalidParams(t *testing.T) {
	d := NewDispatcher()
	d.Register("validate", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		// A validation error wrapped with fmt.Errorf must still be detected via errors.As.
		return nil, fmt.Errorf("invalid params: %w", NewValidationError("bad field"))
	})

	id := json.RawMessage(`6`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "validate",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("expected code %d (Invalid Params), got %d", CodeInvalidParams, resp.Error.Code)
	}
}

func TestDispatch_NonValidationErrorStaysInternal(t *testing.T) {
	d := NewDispatcher()
	d.Register("boom", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return nil, errors.New("disk on fire")
	})

	id := json.RawMessage(`7`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "boom",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != CodeInternalError {
		t.Errorf("expected code %d (Internal Error) for a non-validation error, got %d", CodeInternalError, resp.Error.Code)
	}
}

func TestValidationError_ErrorAndUnwrap(t *testing.T) {
	base := NewValidationError("directory_path is required")
	if base.Error() != "directory_path is required" {
		t.Errorf("Error() = %q, want %q", base.Error(), "directory_path is required")
	}

	wrapped := fmt.Errorf("context: %w", base)
	var ve *ValidationError
	if !errors.As(wrapped, &ve) {
		t.Fatal("expected errors.As to detect wrapped *ValidationError")
	}
	if ve.Error() != "directory_path is required" {
		t.Errorf("unwrapped Error() = %q, want %q", ve.Error(), "directory_path is required")
	}
}
