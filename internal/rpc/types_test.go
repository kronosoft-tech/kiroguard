package rpc

import (
	"encoding/json"
	"testing"
)

func TestParseRequest_Valid(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req, err := ParseRequest([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", req.JSONRPC)
	}
	if req.Method != "tools/list" {
		t.Errorf("expected method tools/list, got %q", req.Method)
	}
	if req.ID == nil {
		t.Error("expected non-nil ID")
	}
}

func TestParseRequest_Notification(t *testing.T) {
	// Notifications have no ID
	input := `{"jsonrpc":"2.0","method":"initialized"}`
	req, err := ParseRequest([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.ID != nil {
		t.Error("expected nil ID for notification")
	}
	if req.Method != "initialized" {
		t.Errorf("expected method initialized, got %q", req.Method)
	}
}

func TestParseRequest_InvalidJSON(t *testing.T) {
	input := `{not valid json}`
	_, err := ParseRequest([]byte(input))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeParseError {
		t.Errorf("expected code %d, got %d", CodeParseError, rpcErr.Code)
	}
}

func TestParseRequest_MissingJSONRPC(t *testing.T) {
	input := `{"method":"test"}`
	_, err := ParseRequest([]byte(input))
	if err == nil {
		t.Fatal("expected error for missing jsonrpc")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", CodeInvalidRequest, rpcErr.Code)
	}
}

func TestParseRequest_WrongJSONRPCVersion(t *testing.T) {
	input := `{"jsonrpc":"1.0","method":"test"}`
	_, err := ParseRequest([]byte(input))
	if err == nil {
		t.Fatal("expected error for wrong jsonrpc version")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", CodeInvalidRequest, rpcErr.Code)
	}
}

func TestParseRequest_MissingMethod(t *testing.T) {
	input := `{"jsonrpc":"2.0"}`
	_, err := ParseRequest([]byte(input))
	if err == nil {
		t.Fatal("expected error for missing method")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", CodeInvalidRequest, rpcErr.Code)
	}
}

func TestParseRequest_EmptyMethod(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":""}`
	_, err := ParseRequest([]byte(input))
	if err == nil {
		t.Fatal("expected error for empty method")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected *RPCError, got %T", err)
	}
	if rpcErr.Code != CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", CodeInvalidRequest, rpcErr.Code)
	}
}

func TestNewResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	resp := NewResponse(&id, map[string]string{"status": "ok"})
	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Error("expected nil error on success response")
	}
	if resp.Result == nil {
		t.Error("expected non-nil result")
	}
	// Verify result is valid JSON containing our value
	var result map[string]string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status ok, got %q", result["status"])
	}
}

func TestNewErrorResponse(t *testing.T) {
	id := json.RawMessage(`"abc"`)
	resp := NewErrorResponse(&id, CodeMethodNotFound, "Method not found: foo")
	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", resp.JSONRPC)
	}
	if resp.Result != nil {
		t.Error("expected nil result on error response")
	}
	if resp.Error == nil {
		t.Fatal("expected non-nil error")
	}
	if resp.Error.Code != CodeMethodNotFound {
		t.Errorf("expected code %d, got %d", CodeMethodNotFound, resp.Error.Code)
	}
	if resp.Error.Message != "Method not found: foo" {
		t.Errorf("unexpected message: %q", resp.Error.Message)
	}
}

func TestNewResponse_NilID(t *testing.T) {
	resp := NewResponse(nil, "result")
	if resp.ID != nil {
		t.Error("expected nil ID")
	}
}

func TestRoundTrip_Request(t *testing.T) {
	original := `{"jsonrpc":"2.0","id":42,"method":"envguard/scan","params":{"diff":"hello"}}`
	req, err := ParseRequest([]byte(original))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Marshal back
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Parse again
	req2, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}

	if req.JSONRPC != req2.JSONRPC {
		t.Error("jsonrpc mismatch after round-trip")
	}
	if req.Method != req2.Method {
		t.Error("method mismatch after round-trip")
	}
}
