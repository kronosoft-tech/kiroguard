package rpc

import (
	"context"
	"testing"
)

func TestClientID_AbsentReturnsEmpty(t *testing.T) {
	if got := ClientID(context.Background()); got != "" {
		t.Errorf("ClientID on empty context = %q, want empty", got)
	}
}

func TestWithClientID_RoundTrip(t *testing.T) {
	ctx := WithClientID(context.Background(), "sess-123")
	if got := ClientID(ctx); got != "sess-123" {
		t.Errorf("ClientID = %q, want %q", got, "sess-123")
	}
}

func TestWithClientID_EmptyIsNoop(t *testing.T) {
	// Setting an empty id must not create a spurious value.
	ctx := WithClientID(context.Background(), "")
	if got := ClientID(ctx); got != "" {
		t.Errorf("ClientID = %q, want empty for empty id", got)
	}
}
