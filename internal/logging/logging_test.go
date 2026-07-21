package logging

import (
	"errors"
	"testing"
)

func TestModuleLogger_ReturnsNonNilLogger(t *testing.T) {
	logger := ModuleLogger("envguard")
	if logger == nil {
		t.Fatal("ModuleLogger returned nil")
	}
}

func TestModuleLogger_DifferentModulesReturnDistinctLoggers(t *testing.T) {
	l1 := ModuleLogger("envguard")
	l2 := ModuleLogger("vulnscanner")
	if l1 == l2 {
		t.Fatal("expected different logger instances for different modules")
	}
}

func TestErrorAttrs_ContainsExpectedFields(t *testing.T) {
	err := errors.New("connection refused")
	attrs := ErrorAttrs("network_timeout", err)

	if len(attrs) != 4 {
		t.Fatalf("expected 4 elements (2 key-value pairs), got %d", len(attrs))
	}

	if attrs[0] != "error_type" {
		t.Errorf("expected first key to be 'error_type', got %v", attrs[0])
	}
	if attrs[1] != "network_timeout" {
		t.Errorf("expected error_type value 'network_timeout', got %v", attrs[1])
	}
	if attrs[2] != "error" {
		t.Errorf("expected third key to be 'error', got %v", attrs[2])
	}
	if attrs[3] != "connection refused" {
		t.Errorf("expected error value 'connection refused', got %v", attrs[3])
	}
}
