package rpc

import "encoding/json"

// Standard JSON-RPC 2.0 error codes.
const (
	// CodeParseError indicates invalid JSON was received by the server.
	CodeParseError = -32700

	// CodeInvalidRequest indicates the JSON sent is not a valid Request object.
	CodeInvalidRequest = -32600

	// CodeMethodNotFound indicates the method does not exist or is not available.
	CodeMethodNotFound = -32601

	// CodeInvalidParams indicates invalid method parameters.
	CodeInvalidParams = -32602

	// CodeInternalError indicates an internal JSON-RPC error.
	CodeInternalError = -32603
)

// ErrParseError returns a Response for a JSON parse error.
func ErrParseError(id *json.RawMessage, detail string) *Response {
	msg := "Parse error"
	if detail != "" {
		msg += ": " + detail
	}
	return NewErrorResponse(id, CodeParseError, msg)
}

// ErrInvalidRequest returns a Response for an invalid JSON-RPC request.
func ErrInvalidRequest(id *json.RawMessage, detail string) *Response {
	msg := "Invalid Request"
	if detail != "" {
		msg += ": " + detail
	}
	return NewErrorResponse(id, CodeInvalidRequest, msg)
}

// ErrMethodNotFound returns a Response for an unknown method.
func ErrMethodNotFound(id *json.RawMessage, method string) *Response {
	msg := "Method not found"
	if method != "" {
		msg += ": " + method
	}
	return NewErrorResponse(id, CodeMethodNotFound, msg)
}

// ErrInvalidParams returns a Response for invalid method parameters.
func ErrInvalidParams(id *json.RawMessage, detail string) *Response {
	msg := "Invalid params"
	if detail != "" {
		msg += ": " + detail
	}
	return NewErrorResponse(id, CodeInvalidParams, msg)
}

// ErrInternalError returns a Response for an internal server error.
func ErrInternalError(id *json.RawMessage, detail string) *Response {
	msg := "Internal error"
	if detail != "" {
		msg += ": " + detail
	}
	return NewErrorResponse(id, CodeInternalError, msg)
}
