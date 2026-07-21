package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// sseClient represents a connected SSE client with a channel for sending events.
type sseClient struct {
	events chan []byte
	done   chan struct{}
}

// SSETransport implements the Transport interface using HTTP with Server-Sent Events.
// POST /message receives JSON-RPC requests and returns responses synchronously.
// GET /sse establishes a persistent SSE connection for server-pushed events.
type SSETransport struct {
	addr    string
	handler MessageHandler

	mu      sync.Mutex
	clients []*sseClient
}

// NewSSETransport creates a new SSE transport listening on the given address (e.g., ":3000").
func NewSSETransport(addr string) *SSETransport {
	return &SSETransport{
		addr: addr,
	}
}

// Start begins the HTTP server with /message and /sse endpoints.
// It blocks until the context is cancelled, then performs graceful shutdown.
func (s *SSETransport) Start(ctx context.Context, handler MessageHandler) error {
	s.handler = handler

	mux := http.NewServeMux()
	mux.HandleFunc("/message", s.handleMessage)
	mux.HandleFunc("/sse", s.handleSSE)

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

// Send broadcasts a JSON-RPC response to all connected SSE clients.
func (s *SSETransport) Send(ctx context.Context, msg *rpc.Response) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("sse transport: marshal response: %w", err)
	}

	s.mu.Lock()
	clients := make([]*sseClient, len(s.clients))
	copy(clients, s.clients)
	s.mu.Unlock()

	for _, c := range clients {
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

	resp, err := s.handler(r.Context(), req)
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
		events: make(chan []byte, 64),
		done:   make(chan struct{}),
	}

	s.addClient(client)
	defer s.removeClient(client)

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

// addClient registers an SSE client for receiving broadcast events.
func (s *SSETransport) addClient(c *sseClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = append(s.clients, c)
}

// removeClient unregisters an SSE client and signals it as done.
func (s *SSETransport) removeClient(c *sseClient) {
	close(c.done)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, client := range s.clients {
		if client == c {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			return
		}
	}
}

// writeJSONError writes a JSON-RPC error response to the HTTP response writer.
func writeJSONError(w http.ResponseWriter, id *json.RawMessage, code int, message string) {
	resp := rpc.NewErrorResponse(id, code, message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors are still 200 OK at HTTP level.
	json.NewEncoder(w).Encode(resp)
}
