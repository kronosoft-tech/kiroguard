package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

func TestStdioTransport_ValidRequest(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}` + "\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		return rpc.NewResponse(req.ID, map[string]string{"status": "ok"}), nil
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// Parse the output response.
	var resp rpc.Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %s", resp.JSONRPC)
	}
	if resp.Error != nil {
		t.Errorf("expected no error, got %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected result to be non-nil")
	}
}

func TestStdioTransport_MalformedJSON(t *testing.T) {
	input := "not-valid-json\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		t.Fatal("handler should not be called for malformed input")
		return nil, nil
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	var resp rpc.Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error response for malformed JSON")
	}
	if resp.Error.Code != rpc.CodeParseError {
		t.Errorf("expected code %d, got %d", rpc.CodeParseError, resp.Error.Code)
	}
}

func TestStdioTransport_InvalidRequest(t *testing.T) {
	// Valid JSON, but missing "jsonrpc" field.
	input := `{"method":"test"}` + "\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		t.Fatal("handler should not be called for invalid request")
		return nil, nil
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	var resp rpc.Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error response for invalid request")
	}
	if resp.Error.Code != rpc.CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", rpc.CodeInvalidRequest, resp.Error.Code)
	}
}

func TestStdioTransport_MultipleRequests(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"a"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"b"}` + "\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	var methods []string
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		methods = append(methods, req.Method)
		return rpc.NewResponse(req.ID, "ok"), nil
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	if len(methods) != 2 {
		t.Fatalf("expected 2 handler calls, got %d", len(methods))
	}
	if methods[0] != "a" || methods[1] != "b" {
		t.Errorf("expected methods [a, b], got %v", methods)
	}

	// Verify two responses were written.
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 response lines, got %d", len(lines))
	}
}

func TestStdioTransport_EmptyLines(t *testing.T) {
	input := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	callCount := 0
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		callCount++
		return rpc.NewResponse(req.ID, "pong"), nil
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 handler call, got %d", callCount)
	}
}

func TestStdioTransport_ContextCancellation(t *testing.T) {
	// Create a pipe where we control what's written.
	pipeR, pipeW := io.Pipe()

	var output bytes.Buffer
	tr := NewStdioTransport(pipeR, &output)

	ctx, cancel := context.WithCancel(context.Background())

	handlerCalled := make(chan struct{}, 1)
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		handlerCalled <- struct{}{}
		return rpc.NewResponse(req.ID, "ok"), nil
	}

	done := make(chan error, 1)
	go func() {
		done <- tr.Start(ctx, handler)
	}()

	// Write one valid request.
	_, err := pipeW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"test"}` + "\n"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for handler to be called.
	<-handlerCalled

	// Cancel context and close the write end to unblock the scanner.
	cancel()
	pipeW.Close()

	result := <-done
	// The transport should exit with either nil or context error.
	if result != nil && result != context.Canceled {
		t.Fatalf("expected nil or context.Canceled, got %v", result)
	}
}

func TestStdioTransport_Send(t *testing.T) {
	var output bytes.Buffer
	tr := NewStdioTransport(nil, &output)

	id := json.RawMessage(`42`)
	resp := rpc.NewResponse(&id, "hello")

	err := tr.Send(context.Background(), resp)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	// Output should be valid JSON followed by a newline.
	raw := output.String()
	if !strings.HasSuffix(raw, "\n") {
		t.Error("expected output to end with newline")
	}

	var got rpc.Response
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("failed to unmarshal sent response: %v", err)
	}
	if got.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %s", got.JSONRPC)
	}
}

type errReader struct{ err error }

func (r *errReader) Read(p []byte) (int, error) { return 0, r.err }

type errWriter struct {
	written bytes.Buffer
	failAt  int // bytes written before failure
}

func (w *errWriter) Write(p []byte) (int, error) {
	remaining := w.failAt - w.written.Len()
	if remaining <= 0 {
		return 0, io.ErrClosedPipe
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return w.written.Write(p)
}

func TestStdioTransport_ScannerError(t *testing.T) {
	reader := &errReader{err: io.ErrUnexpectedEOF}
	var output bytes.Buffer
	tr := NewStdioTransport(reader, &output)

	err := tr.Start(context.Background(), func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		t.Fatal("handler should not be called on scanner error")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected scanner error, got nil")
	}
}

func TestStdioTransport_SendError_Propagated(t *testing.T) {
	// Use a writer that fails immediately.
	writer := &errWriter{failAt: 0}
	input := `{"jsonrpc":"2.0","id":1,"method":"test","params":{}}` + "\n"
	tr := NewStdioTransport(strings.NewReader(input), writer)

	err := tr.Start(context.Background(), func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		return rpc.NewResponse(req.ID, "ok"), nil
	})
	if err == nil {
		t.Fatal("expected send error, got nil")
	}
}

func TestStdioTransport_ParseError_SendFailure(t *testing.T) {
	// When parse fails AND send also fails, Start returns the send error.
	writer := &errWriter{failAt: 0}
	input := `not-json` + "\n"
	tr := NewStdioTransport(strings.NewReader(input), writer)

	err := tr.Start(context.Background(), func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		t.Fatal("handler should not be called on parse error")
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected error from send failure after parse error, got nil")
	}
}

func TestStdioTransport_HandlerError(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"fail"}` + "\n"
	reader := strings.NewReader(input)
	var output bytes.Buffer

	tr := NewStdioTransport(reader, &output)

	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		return nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "something went wrong"}
	}

	err := tr.Start(context.Background(), handler)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	var resp rpc.Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error response")
	}
	if resp.Error.Code != rpc.CodeInternalError {
		t.Errorf("expected code %d, got %d", rpc.CodeInternalError, resp.Error.Code)
	}
}
