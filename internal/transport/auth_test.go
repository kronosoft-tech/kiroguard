package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAuthedSSE(token string) (*SSETransport, *httptest.Server) {
	tr := NewSSETransport(":0")
	tr.handler = echoHandler
	tr.SetAuthToken(token)

	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	mux.HandleFunc("/sse", tr.handleSSE)
	return tr, httptest.NewServer(mux)
}

func TestSSETransport_Auth_RejectsMissingToken(t *testing.T) {
	_, ts := newAuthedSSE("s3cret")
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when Authorization is missing", resp.StatusCode)
	}
}

func TestSSETransport_Auth_RejectsWrongToken(t *testing.T) {
	_, ts := newAuthedSSE("s3cret")
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for wrong token", resp.StatusCode)
	}
}

func TestSSETransport_Auth_AcceptsValidToken(t *testing.T) {
	_, ts := newAuthedSSE("s3cret")
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for valid token", resp.StatusCode)
	}
}

func TestSSETransport_Auth_SSEEndpointRequiresToken(t *testing.T) {
	_, ts := newAuthedSSE("s3cret")
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/sse", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /sse failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for /sse without token", resp.StatusCode)
	}
}

func TestSSETransport_Auth_DisabledByDefault(t *testing.T) {
	// No token set → endpoints remain open (backward compatible).
	tr := NewSSETransport(":0")
	tr.handler = echoHandler
	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	resp, err := http.Post(ts.URL+"/message", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 when auth disabled", resp.StatusCode)
	}
}

// postEcho POSTs an echo request with an optional bearer token and returns the status.
func postEcho(t *testing.T, url, token string) int {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, url+"/message", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestSSETransport_Auth_MultipleTokensAccepted(t *testing.T) {
	tr := NewSSETransport(":0")
	tr.handler = echoHandler
	tr.SetAuthTokens([]string{"old-key", "new-key"})

	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if got := postEcho(t, ts.URL, "old-key"); got != http.StatusOK {
		t.Errorf("old-key status = %d, want 200", got)
	}
	if got := postEcho(t, ts.URL, "new-key"); got != http.StatusOK {
		t.Errorf("new-key status = %d, want 200", got)
	}
	if got := postEcho(t, ts.URL, "bogus"); got != http.StatusUnauthorized {
		t.Errorf("bogus status = %d, want 401", got)
	}
}

func TestSSETransport_Auth_HotRotation(t *testing.T) {
	tr := NewSSETransport(":0")
	tr.handler = echoHandler
	tr.SetAuthToken("t1")

	mux := http.NewServeMux()
	mux.HandleFunc("/message", tr.handleMessage)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if got := postEcho(t, ts.URL, "t1"); got != http.StatusOK {
		t.Fatalf("t1 status before rotation = %d, want 200", got)
	}

	// Rotate to a new token set WITHOUT restarting the server.
	tr.SetAuthTokens([]string{"t2"})

	if got := postEcho(t, ts.URL, "t1"); got != http.StatusUnauthorized {
		t.Errorf("t1 status after rotation = %d, want 401 (revoked)", got)
	}
	if got := postEcho(t, ts.URL, "t2"); got != http.StatusOK {
		t.Errorf("t2 status after rotation = %d, want 200", got)
	}
}
