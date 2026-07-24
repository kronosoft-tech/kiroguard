package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// echoHandler is a test MessageHandler that echoes back the method as the result.
func echoHandler(_ context.Context, req *rpc.Request) (*rpc.Response, error) {
	return rpc.NewResponse(req.ID, map[string]string{"echo": req.Method}), nil
}

func TestSSETransport_PostMessage_ValidRequest(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", transport.handleMessage)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /message failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var rpcResp rpc.Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if rpcResp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", rpcResp.JSONRPC)
	}
	if rpcResp.Error != nil {
		t.Errorf("expected no error, got: %v", rpcResp.Error)
	}
	if rpcResp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	var result map[string]string
	if err := json.Unmarshal(rpcResp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if result["echo"] != "test.echo" {
		t.Errorf("expected echo=test.echo, got %s", result["echo"])
	}
}

func TestSSETransport_PostMessage_InvalidJSON(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", transport.handleMessage)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("POST /message failed: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp rpc.Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if rpcResp.Error == nil {
		t.Fatal("expected error response for invalid JSON")
	}
	if rpcResp.Error.Code != rpc.CodeParseError {
		t.Errorf("expected code %d, got %d", rpc.CodeParseError, rpcResp.Error.Code)
	}
}

func TestSSETransport_PostMessage_MissingMethod(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", transport.handleMessage)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	reqBody := `{"jsonrpc":"2.0","id":1}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /message failed: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp rpc.Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if rpcResp.Error == nil {
		t.Fatal("expected error response for missing method")
	}
	if rpcResp.Error.Code != rpc.CodeInvalidRequest {
		t.Errorf("expected code %d, got %d", rpc.CodeInvalidRequest, rpcResp.Error.Code)
	}
}

func TestSSETransport_PostMessage_WrongHTTPMethod(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", transport.handleMessage)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/message")
	if err != nil {
		t.Fatalf("GET /message failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestSSETransport_SSE_HeadersAndStream(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Use httptest.NewRecorder won't work for streaming. We use an HTTP client
	// with a context that we cancel after verifying headers.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// The client.Do returns once headers are flushed (we flush immediately in the handler).
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}
	defer func() {
		cancel()
		resp.Body.Close()
	}()

	// Verify headers.
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("expected Cache-Control no-cache, got %s", cc)
	}
}

func TestSSETransport_SSE_ReceivesBroadcast(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}
	defer resp.Body.Close()

	// Give the SSE connection time to register.
	time.Sleep(100 * time.Millisecond)

	// Send a response via broadcast.
	id := json.RawMessage(`1`)
	testResp := rpc.NewResponse(&id, map[string]string{"hello": "world"})
	if err := transport.Send(context.Background(), testResp); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Read the SSE event from the stream.
	scanner := bufio.NewScanner(resp.Body)
	var eventData string
	deadline := time.After(3 * time.Second)

	dataCh := make(chan string, 1)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			// Skip the initial endpoint event; we want the broadcast payload.
			if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "/message?sessionId=") {
				dataCh <- strings.TrimPrefix(line, "data: ")
				return
			}
		}
	}()

	select {
	case eventData = <-dataCh:
	case <-deadline:
		t.Fatal("timed out waiting for SSE event")
	}

	if eventData == "" {
		t.Fatal("did not receive SSE event data")
	}

	var received rpc.Response
	if err := json.Unmarshal([]byte(eventData), &received); err != nil {
		t.Fatalf("failed to unmarshal SSE event: %v", err)
	}

	if received.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", received.JSONRPC)
	}

	var result map[string]string
	if err := json.Unmarshal(received.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if result["hello"] != "world" {
		t.Errorf("expected hello=world, got %s", result["hello"])
	}
}

func TestSSETransport_SSE_KeepaliveWithin35Seconds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping keepalive test in short mode")
	}

	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}
	defer resp.Body.Close()

	// Read lines until we get a keepalive comment or timeout.
	dataCh := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == ": keepalive" {
				dataCh <- true
				return
			}
		}
		dataCh <- false
	}()

	select {
	case got := <-dataCh:
		if !got {
			t.Error("did not receive keepalive comment")
		}
	case <-time.After(35 * time.Second):
		t.Error("timed out waiting for keepalive comment (>35s)")
	}
}

func TestSSETransport_SSE_WrongHTTPMethod(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/sse", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST /sse failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", resp.StatusCode)
	}
}

func TestSSETransport_Start_And_GracefulShutdown(t *testing.T) {
	transport := NewSSETransport(":0")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx, echoHandler)
	}()

	// Give the server time to start.
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestSSETransport_Send_MultipleClients(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	const numClients = 3

	type clientResult struct {
		resp    *http.Response
		scanner *bufio.Scanner
		cancel  context.CancelFunc
	}

	clients := make([]clientResult, numClients)

	for i := 0; i < numClients; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
		if err != nil {
			t.Fatalf("failed to create request %d: %v", i, err)
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			t.Fatalf("GET /sse failed for client %d: %v", i, err)
		}
		clients[i] = clientResult{resp: resp, scanner: bufio.NewScanner(resp.Body), cancel: cancel}
	}
	defer func() {
		for _, c := range clients {
			c.cancel()
			c.resp.Body.Close()
		}
	}()

	// Let all clients register.
	time.Sleep(150 * time.Millisecond)

	// Broadcast a message.
	id := json.RawMessage(`42`)
	testResp := rpc.NewResponse(&id, map[string]string{"multi": "cast"})
	if err := transport.Send(context.Background(), testResp); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Verify each client received the event.
	for i, c := range clients {
		dataCh := make(chan string, 1)
		go func(s *bufio.Scanner) {
			for s.Scan() {
				line := s.Text()
				// Skip the initial endpoint event; we want the broadcast payload.
				if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "/message?sessionId=") {
					dataCh <- strings.TrimPrefix(line, "data: ")
					return
				}
			}
		}(c.scanner)

		select {
		case eventData := <-dataCh:
			var received rpc.Response
			if err := json.Unmarshal([]byte(eventData), &received); err != nil {
				t.Errorf("client %d: failed to unmarshal: %v", i, err)
				continue
			}

			var result map[string]string
			if err := json.Unmarshal(received.Result, &result); err != nil {
				t.Errorf("client %d: failed to unmarshal result: %v", i, err)
				continue
			}
			if result["multi"] != "cast" {
				t.Errorf("client %d: expected multi=cast, got %s", i, result["multi"])
			}
		case <-time.After(3 * time.Second):
			t.Errorf("client %d: timed out waiting for event", i)
		}
	}
}

func TestSSETransport_Send_DisconnectedClient_DropsMessage(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}

	// Read endpoint event and get session ID
	scanner := bufio.NewScanner(resp.Body)
	sessionID := readEndpointSessionID(t, scanner)

	// Close response body and cancel context to disconnect the client
	resp.Body.Close()
	cancel()
	time.Sleep(50 * time.Millisecond) // let the disconnect propagate

	// Send targeted at the now-disconnected session — must not block
	id := json.RawMessage(`1`)
	msg := rpc.NewResponse(&id, map[string]string{"status": "dropped"})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if err := transport.Send(rpc.WithClientID(ctx2, sessionID), msg); err != nil {
		t.Fatalf("Send to disconnected client failed: %v", err)
	}
}

func TestSSETransport_SetAuthToken_EmptyDisablesAuth(t *testing.T) {
	tr := NewSSETransport(":0")
	tr.handler = echoHandler
	tr.SetAuthToken("") // should clear tokens

	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Must be accessible without token
	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 after SetAuthToken('')", resp.StatusCode)
	}
}

func TestSSETransport_Start_ListenError(t *testing.T) {
	tr := NewSSETransport(":-1") // invalid port

	err := tr.Start(context.Background(), echoHandler)
	if err == nil {
		t.Fatal("expected listen error, got nil")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("expected listen error, got: %v", err)
	}
}

func TestSSETransport_PostMessage_HandlerError(t *testing.T) {
	tr := NewSSETransport(":0")
	errorHandler := func(_ context.Context, req *rpc.Request) (*rpc.Response, error) {
		return nil, fmt.Errorf("handler failed: something went wrong")
	}
	tr.handler = errorHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":7,"method":"test.fail","params":{}}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	var rpcResp rpc.Response
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if rpcResp.Error == nil {
		t.Fatal("expected error response when handler fails")
	}
	if rpcResp.Error.Code != rpc.CodeInternalError {
		t.Errorf("expected code %d, got %d", rpc.CodeInternalError, rpcResp.Error.Code)
	}
}

func TestSSETransport_ImplementsInterface(t *testing.T) {
	// Compile-time check that SSETransport implements Transport.
	var _ Transport = (*SSETransport)(nil)
	fmt.Println("SSETransport implements Transport interface")
}

// readEndpointSessionID scans an SSE stream for the initial endpoint event and
// returns the sessionId query value from its data line.
func readEndpointSessionID(t *testing.T, scanner *bufio.Scanner) string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	found := make(chan string, 1)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			const marker = "data: /message?sessionId="
			if strings.HasPrefix(line, marker) {
				found <- strings.TrimPrefix(line, marker)
				return
			}
		}
	}()
	select {
	case id := <-found:
		return id
	case <-deadline:
		t.Fatal("timed out waiting for endpoint event")
		return ""
	}
}

func TestSSETransport_SSE_SendsEndpointEvent(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}
	defer resp.Body.Close()

	id := readEndpointSessionID(t, bufio.NewScanner(resp.Body))
	if id == "" {
		t.Fatal("expected a non-empty sessionId in endpoint event")
	}
}

func TestSSETransport_Send_RoutesToSpecificSession(t *testing.T) {
	transport := NewSSETransport(":0")
	transport.handler = echoHandler

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", transport.handleSSE)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect two clients.
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	reqA, _ := http.NewRequestWithContext(ctxA, http.MethodGet, ts.URL+"/sse", nil)
	respA, err := (&http.Client{}).Do(reqA)
	if err != nil {
		t.Fatalf("client A connect failed: %v", err)
	}
	defer respA.Body.Close()
	scannerA := bufio.NewScanner(respA.Body)
	idA := readEndpointSessionID(t, scannerA)

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	reqB, _ := http.NewRequestWithContext(ctxB, http.MethodGet, ts.URL+"/sse", nil)
	respB, err := (&http.Client{}).Do(reqB)
	if err != nil {
		t.Fatalf("client B connect failed: %v", err)
	}
	defer respB.Body.Close()
	scannerB := bufio.NewScanner(respB.Body)
	idB := readEndpointSessionID(t, scannerB)

	if idA == idB {
		t.Fatalf("expected distinct session ids, both = %q", idA)
	}

	// Give registration a moment.
	time.Sleep(100 * time.Millisecond)

	// Send targeted at client A only.
	id := json.RawMessage(`1`)
	msg := rpc.NewResponse(&id, map[string]string{"target": "A"})
	if err := transport.Send(rpc.WithClientID(context.Background(), idA), msg); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Client A must receive the data event.
	aData := make(chan string, 1)
	go func() {
		for scannerA.Scan() {
			line := scannerA.Text()
			if strings.HasPrefix(line, "data: ") {
				aData <- strings.TrimPrefix(line, "data: ")
				return
			}
		}
	}()
	select {
	case data := <-aData:
		var received rpc.Response
		if err := json.Unmarshal([]byte(data), &received); err != nil {
			t.Fatalf("client A unmarshal failed: %v", err)
		}
		var result map[string]string
		json.Unmarshal(received.Result, &result)
		if result["target"] != "A" {
			t.Errorf("client A got target=%q, want A", result["target"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client A did not receive the targeted message")
	}

	// Client B must NOT receive anything within a short window.
	bData := make(chan string, 1)
	go func() {
		for scannerB.Scan() {
			line := scannerB.Text()
			if strings.HasPrefix(line, "data: ") {
				bData <- strings.TrimPrefix(line, "data: ")
				return
			}
		}
	}()
	select {
	case data := <-bData:
		t.Errorf("client B unexpectedly received a message: %s", data)
	case <-time.After(600 * time.Millisecond):
		// Expected: no message routed to B.
	}
}
