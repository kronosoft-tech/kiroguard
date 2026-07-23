// Package rpc implements JSON-RPC 2.0 types and request routing for KiroGuard.
package rpc

import "encoding/json"

// Request represents a JSON-RPC 2.0 request object.
type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response object.
//
// It also doubles as the envelope for server-initiated notifications: when
// Method (and optionally Params) is set and ID is nil, it serializes as a valid
// JSON-RPC notification (no id, no result/error). Use NewNotification to build one.
type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ParseRequest validates raw bytes as a JSON-RPC 2.0 request.
// It checks:
//  1. Valid JSON
//  2. "jsonrpc" field equals "2.0"
//  3. "method" field is a non-empty string
//
// ID and Params are optional.
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, NewRPCError(CodeParseError, "invalid JSON: "+err.Error())
	}

	if req.JSONRPC != "2.0" {
		return nil, NewRPCError(CodeInvalidRequest, `missing or invalid "jsonrpc" field, must be "2.0"`)
	}

	if req.Method == "" {
		return nil, NewRPCError(CodeInvalidRequest, `missing or empty "method" field`)
	}

	return &req, nil
}

// NewResponse creates a success JSON-RPC 2.0 response.
// The result value is marshaled to JSON. If marshaling fails, an internal error
// response is returned instead.
func NewResponse(id *json.RawMessage, result interface{}) *Response {
	data, err := json.Marshal(result)
	if err != nil {
		return NewErrorResponse(id, CodeInternalError, "failed to marshal result: "+err.Error())
	}
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  data,
	}
}

// NewErrorResponse creates an error JSON-RPC 2.0 response.
func NewErrorResponse(id *json.RawMessage, code int, message string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
}

// NewRPCError creates a new RPCError with the given code and message.
func NewRPCError(code int, message string) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
	}
}

// Error implements the error interface for RPCError.
func (e *RPCError) Error() string {
	return e.Message
}
