package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// ToolHandler is the signature for MCP tool handlers.
// It receives a context and the raw JSON params from the request,
// and returns a result value or an error.
type ToolHandler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// Dispatcher routes incoming JSON-RPC requests to registered tool handlers.
// It is safe for concurrent use by multiple goroutines.
type Dispatcher struct {
	mu       sync.RWMutex
	handlers map[string]ToolHandler
}

// NewDispatcher creates a new Dispatcher with an empty handler registry.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string]ToolHandler),
	}
}

// Register adds a tool handler for the given method name.
// It is safe to call from multiple goroutines.
func (d *Dispatcher) Register(method string, h ToolHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[method] = h
}

// Dispatch routes a JSON-RPC request to the appropriate handler and returns
// the response. It recovers from panics in handlers and converts them to
// internal error responses (-32603).
func (d *Dispatcher) Dispatch(ctx context.Context, req *Request) *Response {
	return d.dispatchSafe(ctx, req)
}

// dispatchSafe wraps the handler invocation with panic recovery.
func (d *Dispatcher) dispatchSafe(ctx context.Context, req *Request) (resp *Response) {
	defer func() {
		if r := recover(); r != nil {
			resp = ErrInternalError(req.ID, fmt.Sprintf("panic: %v", r))
		}
	}()

	d.mu.RLock()
	handler, ok := d.handlers[req.Method]
	d.mu.RUnlock()

	if !ok {
		return ErrMethodNotFound(req.ID, req.Method)
	}

	result, err := handler(ctx, req.Params)
	if err != nil {
		// Parameter validation failures map to Invalid Params (-32602);
		// everything else is an Internal Error (-32603).
		var ve *ValidationError
		if errors.As(err, &ve) {
			return ErrInvalidParams(req.ID, err.Error())
		}
		return ErrInternalError(req.ID, err.Error())
	}

	return NewResponse(req.ID, result)
}
