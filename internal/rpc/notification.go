package rpc

import (
	"context"
	"encoding/json"
)

// Notifier is the minimal capability needed to push a server-initiated message
// to the connected client(s). The transport layer satisfies this interface via
// its Send method, allowing handlers to emit asynchronous JSON-RPC notifications
// (e.g. progressive enrichment) without depending on the transport package.
type Notifier interface {
	Send(ctx context.Context, msg *Response) error
}

// NewNotification builds a JSON-RPC 2.0 notification: a message with a method
// and params but no id. If params cannot be marshaled, Params is left nil.
func NewNotification(method string, params interface{}) *Response {
	n := &Response{
		JSONRPC: "2.0",
		Method:  method,
	}
	if params != nil {
		if data, err := json.Marshal(params); err == nil {
			n.Params = data
		}
	}
	return n
}
