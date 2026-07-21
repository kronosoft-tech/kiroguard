package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// StdioTransport implements the Transport interface using newline-delimited
// JSON over stdin/stdout. Each line on the input reader is expected to be a
// complete JSON-RPC 2.0 request. Responses are written as one JSON object per
// line to the output writer.
type StdioTransport struct {
	reader io.Reader
	writer io.Writer
	mu     sync.Mutex // guards writes to writer
}

// NewStdioTransport creates a StdioTransport that reads from r and writes to w.
func NewStdioTransport(r io.Reader, w io.Writer) *StdioTransport {
	return &StdioTransport{
		reader: r,
		writer: w,
	}
}

// Start reads newline-delimited JSON from the reader in a loop, parses each
// line as a JSON-RPC 2.0 request, invokes the handler, and sends the response.
// It returns nil on EOF or when the context is cancelled.
func (t *StdioTransport) Start(ctx context.Context, handler MessageHandler) error {
	scanner := bufio.NewScanner(t.reader)

	for scanner.Scan() {
		// Check if the context has been cancelled.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		req, err := rpc.ParseRequest(line)
		if err != nil {
			// ParseRequest returns an *RPCError on failure.
			rpcErr, ok := err.(*rpc.RPCError)
			if ok {
				resp := rpc.NewErrorResponse(nil, rpcErr.Code, rpcErr.Message)
				if sendErr := t.Send(ctx, resp); sendErr != nil {
					return sendErr
				}
			}
			continue
		}

		resp, handlerErr := handler(ctx, req)
		if handlerErr != nil {
			resp = rpc.NewErrorResponse(req.ID, rpc.CodeInternalError, handlerErr.Error())
		}
		if resp != nil {
			if sendErr := t.Send(ctx, resp); sendErr != nil {
				return sendErr
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// EOF reached — normal shutdown.
	return nil
}

// Send writes a JSON-RPC 2.0 response as a single line to the output writer.
// It is safe to call from multiple goroutines.
func (t *StdioTransport) Send(ctx context.Context, msg *rpc.Response) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Write JSON followed by a newline.
	data = append(data, '\n')
	_, err = t.writer.Write(data)
	return err
}
