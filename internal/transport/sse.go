package transport

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// sseClient represents a connected SSE client with a channel for sending events.
type sseClient struct {
	id     string
	events chan []byte
	done   chan struct{}
}

// newSessionID returns a random hex session identifier for an SSE connection.
func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a time-based id; collisions are astronomically unlikely
		// and this path only triggers if the OS RNG fails.
		return fmt.Sprintf("sess-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// SSETransport implements the Transport interface using HTTP with Server-Sent Events.
// POST /message receives JSON-RPC requests and returns responses synchronously.
// GET /sse establishes a persistent SSE connection for server-pushed events.
type SSETransport struct {
	addr    string
	handler MessageHandler

	// authTokens holds the set of accepted bearer tokens. When empty/nil, auth is
	// disabled (local/dev). Stored atomically so tokens can be rotated at runtime
	// without restarting the server or locking the request path.
	authTokens atomic.Pointer[[]string]

	// ready marks the server as ready for /healthz liveness/readiness probes.
	ready atomic.Bool

	// metricsSnapshotters collects registered metric providers for the /metrics endpoint.
	muMetrics sync.Mutex
	snapshotters []MetricsSnapshotter

	mu      sync.Mutex
	clients map[string]*sseClient
}

// NewSSETransport creates a new SSE transport listening on the given address (e.g., ":3000").
func NewSSETransport(addr string) *SSETransport {
	return &SSETransport{
		addr:    addr,
		clients: make(map[string]*sseClient),
	}
}

// SetAuthToken sets a single accepted bearer token (convenience for the common
// case). An empty token leaves the endpoints open.
func (s *SSETransport) SetAuthToken(token string) {
	if token == "" {
		s.SetAuthTokens(nil)
		return
	}
	s.SetAuthTokens([]string{token})
}

// SetReady marks the server as ready (true) or not (false) for /healthz probes.
func (s *SSETransport) SetReady(v bool) {
	s.ready.Store(v)
}

// RegisterMetricsSnapshotter registers a provider whose key-value pairs are
// included in the /metrics endpoint response. Safe to call before Start.
func (s *SSETransport) RegisterMetricsSnapshotter(snapper MetricsSnapshotter) {
	s.muMetrics.Lock()
	defer s.muMetrics.Unlock()
	s.snapshotters = append(s.snapshotters, snapper)
}

// SetAuthTokens replaces the set of accepted bearer tokens atomically. Safe to
// call at runtime to rotate credentials (add the new token, roll clients over,
// then drop the old one) without restarting the server. Empty tokens are
// ignored; an empty resulting set disables authentication.
func (s *SSETransport) SetAuthTokens(tokens []string) {
	cleaned := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if tok != "" {
			cleaned = append(cleaned, tok)
		}
	}
	s.authTokens.Store(&cleaned)
}

// authorized reports whether the request carries an accepted bearer token.
// Comparison is constant-time to avoid leaking tokens via timing.
func (s *SSETransport) authorized(r *http.Request) bool {
	tokensPtr := s.authTokens.Load()
	if tokensPtr == nil || len(*tokensPtr) == 0 {
		return true // auth disabled
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := []byte(strings.TrimPrefix(h, prefix))

	ok := false
	for _, tok := range *tokensPtr {
		if subtle.ConstantTimeCompare(got, []byte(tok)) == 1 {
			ok = true // keep scanning to avoid early-exit timing signal
		}
	}
	return ok
}

// Start begins the HTTP server with /message and /sse endpoints.
// It blocks until the context is cancelled, then performs graceful shutdown.
func (s *SSETransport) Start(ctx context.Context, handler MessageHandler) error {
	s.handler = handler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", s.handleMessage)
	mux.HandleFunc("/sse", s.handleSSE)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)

	server := &http.Server{
		Handler: mux,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sse transport: listen: %w", err)
	}

	// Run the server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		// Graceful shutdown with a 5-second deadline.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("sse transport: shutdown: %w", err)
		}
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Send delivers a JSON-RPC message to connected SSE clients. If ctx carries a
// client id (rpc.ClientID), the message is routed only to that session; if the
// session is gone, the message is dropped. When no client id is present, the
// message is broadcast to all connected clients (backward-compatible behavior).
func (s *SSETransport) Send(ctx context.Context, msg *rpc.Response) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("sse transport: marshal response: %w", err)
	}

	targetID := rpc.ClientID(ctx)

	s.mu.Lock()
	var targets []*sseClient
	if targetID != "" {
		if c, ok := s.clients[targetID]; ok {
			targets = append(targets, c)
		}
		// Unknown/disconnected session → nothing to deliver.
	} else {
		targets = make([]*sseClient, 0, len(s.clients))
		for _, c := range s.clients {
			targets = append(targets, c)
		}
	}
	s.mu.Unlock()

	for _, c := range targets {
		select {
		case c.events <- data:
		case <-c.done:
			// Client already disconnected, skip.
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// handleMessage handles POST /message requests containing JSON-RPC payloads.
func (s *SSETransport) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, nil, rpc.CodeParseError, "failed to read request body")
		return
	}
	defer r.Body.Close()

	req, err := rpc.ParseRequest(body)
	if err != nil {
		// Return the parse/validation error as a JSON-RPC error response.
		if rpcErr, ok := err.(*rpc.RPCError); ok {
			writeJSONError(w, nil, rpcErr.Code, rpcErr.Message)
		} else {
			writeJSONError(w, nil, rpc.CodeParseError, err.Error())
		}
		return
	}

	// Correlate this request with the caller's SSE session (if any) so that
	// asynchronous notifications can be routed back to the originating client.
	ctx := rpc.WithClientID(r.Context(), r.URL.Query().Get("sessionId"))

	resp, err := s.handler(ctx, req)
	if err != nil {
		writeJSONError(w, req.ID, rpc.CodeInternalError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// At this point headers may already be sent; log internally.
		return
	}
}

// handleSSE handles GET /sse requests, establishing a Server-Sent Events stream.
func (s *SSETransport) handleSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Flush headers immediately so the client gets a response.
	flusher.Flush()

	client := &sseClient{
		id:     newSessionID(),
		events: make(chan []byte, 64),
		done:   make(chan struct{}),
	}

	s.addClient(client)
	defer s.removeClient(client)

	// Tell the client which endpoint to POST to, tagged with its session id.
	// This mirrors the MCP HTTP+SSE "endpoint" event and lets the server route
	// per-session notifications back to this connection.
	fmt.Fprintf(w, "event: endpoint\ndata: /message?sessionId=%s\n\n", client.id)
	flusher.Flush()

	// Keep-alive ticker sends a comment event every 30 seconds.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Use the request context to detect client disconnect.
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case data := <-client.events:
			// Send data as an SSE event.
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			// Send keep-alive comment.
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// addClient registers an SSE client (by session id) for receiving events.
func (s *SSETransport) addClient(c *sseClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.id] = c
}

// removeClient unregisters an SSE client and signals it as done.
func (s *SSETransport) removeClient(c *sseClient) {
	close(c.done)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, c.id)
}

// handleHealthz serves GET /healthz for liveness and readiness probes. Returns
// 200 when the server is ready, 503 otherwise.
func (s *SSETransport) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "starting"})
	}
}

// handleMetrics serves GET /metrics returning a combined JSON snapshot of all
// registered module-level operational counters.
func (s *SSETransport) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.muMetrics.Lock()
	copy := make([]MetricsSnapshotter, len(s.snapshotters))
	for i, sn := range s.snapshotters {
		copy[i] = sn
	}
	s.muMetrics.Unlock()

	merged := make(map[string]interface{})
	for _, sn := range copy {
		for k, v := range sn() {
			merged[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(merged)
}

// writeJSONError writes a JSON-RPC error response to the HTTP response writer.
func writeJSONError(w http.ResponseWriter, id *json.RawMessage, code int, message string) {
	resp := rpc.NewErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are still 200 OK at HTTP level.
	json.NewEncoder(w).Encode(resp)
}
