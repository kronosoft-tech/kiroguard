// Package transport implements the MCP transport layer (stdio and HTTP+SSE).
package transport

import (
	"context"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// MessageHandler is a function that processes an incoming JSON-RPC request
// and returns a response or an error.
type MessageHandler func(ctx context.Context, req *rpc.Request) (*rpc.Response, error)

// Transport defines the interface for MCP communication transports.
type Transport interface {
	// Start begins listening for incoming requests and calls handler for each one.
	// It blocks until the context is cancelled or an unrecoverable error occurs.
	Start(ctx context.Context, handler MessageHandler) error

	// Send writes a response message back to the connected client(s).
	Send(ctx context.Context, msg *rpc.Response) error
}
