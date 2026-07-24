package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewNotification_Serialization(t *testing.T) {
	n := NewNotification("notifications/message", map[string]string{"hello": "world"})

	if n.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want 2.0", n.JSONRPC)
	}
	if n.ID != nil {
		t.Error("a notification must have no id")
	}
	if n.Method != "notifications/message" {
		t.Errorf("Method = %q, want notifications/message", n.Method)
	}

	data, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	s := string(data)

	if !strings.Contains(s, `"method":"notifications/message"`) {
		t.Errorf("serialized notification missing method: %s", s)
	}
	if !strings.Contains(s, `"params":`) {
		t.Errorf("serialized notification missing params: %s", s)
	}
	// A notification must not serialize id, result or error fields.
	if strings.Contains(s, `"id"`) {
		t.Errorf("notification must not contain id: %s", s)
	}
	if strings.Contains(s, `"result"`) {
		t.Errorf("notification must not contain result: %s", s)
	}
	if strings.Contains(s, `"error"`) {
		t.Errorf("notification must not contain error: %s", s)
	}

	var params map[string]string
	if err := json.Unmarshal(n.Params, &params); err != nil {
		t.Fatalf("failed to unmarshal params: %v", err)
	}
	if params["hello"] != "world" {
		t.Errorf("params[hello] = %q, want world", params["hello"])
	}
}

// captureSink is a minimal Notifier implementation used to prove the interface
// is satisfied by anything exposing Send(ctx, *Response) error (the same shape
// as the transport layer).
type captureSink struct {
	last *Response
}

func (c *captureSink) Send(_ context.Context, msg *Response) error {
	c.last = msg
	return nil
}

func TestNotifier_InterfaceSatisfied(t *testing.T) {
	var n Notifier = &captureSink{}
	if err := n.Send(context.Background(), NewNotification("notifications/message", nil)); err != nil {
		t.Fatalf("Send error: %v", err)
	}
}
