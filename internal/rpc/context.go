package rpc

import "context"

// clientIDKey is the unexported context key under which a per-connection client
// (session) id is stored. Using a private type prevents collisions with keys
// from other packages.
type clientIDKey struct{}

// WithClientID returns a copy of ctx carrying the given client/session id.
// An empty id is a no-op so callers can pass through unconditionally.
func WithClientID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIDKey{}, id)
}

// ClientID extracts the client/session id from ctx, or "" if none is present.
// Notifiers use this to route a message to a single client; an empty id means
// "broadcast to all".
func ClientID(ctx context.Context) string {
	if id, ok := ctx.Value(clientIDKey{}).(string); ok {
		return id
	}
	return ""
}
