// Package logging provides structured logging utilities for KiroGuard modules.
package logging

import "log/slog"

// ModuleLogger returns a logger with the module name pre-attached.
func ModuleLogger(module string) *slog.Logger {
	return slog.Default().With("module", module)
}

// ErrorAttrs returns common error attributes for structured logging.
// Use with slog methods: logger.Error("msg", ErrorAttrs("type", err)...)
func ErrorAttrs(errorType string, err error) []any {
	return []any{
		"error_type", errorType,
		"error", err.Error(),
	}
}
