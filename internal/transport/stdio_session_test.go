package transport

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// TestStdioTransport_InjectsImplicitSession verifies that stdio (a single-client
// transport) tags the request context with an implicit session id, so modules
// that gate async enrichment on rpc.ClientID still work over stdio — with no
// cross-client leak risk since there is exactly one client.
func TestStdioTransport_InjectsImplicitSession(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"test.echo","params":{}}` + "\n")
	var out bytes.Buffer
	tr := NewStdioTransport(in, &out)

	var gotID string
	handler := func(ctx context.Context, req *rpc.Request) (*rpc.Response, error) {
		gotID = rpc.ClientID(ctx)
		return rpc.NewResponse(req.ID, map[string]string{"ok": "1"}), nil
	}

	if err := tr.Start(context.Background(), handler); err != nil {
		t.Fatalf("Start error: %v", err)
	}

	if gotID == "" {
		t.Error("expected stdio to inject a non-empty implicit session id into the context")
	}
}
