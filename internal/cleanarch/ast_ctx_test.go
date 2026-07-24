package cleanarch

import (
	"context"
	"path/filepath"
	"testing"
)

func TestBuildImportGraphContext_CancelledReturnsPartialNoError(t *testing.T) {
	tmpDir := t.TempDir()

	// A few packages with external imports.
	createGoFile(t, filepath.Join(tmpDir, "a"), "a.go", `package a

import "example.com/x"

var _ = x.Y
`)
	createGoFile(t, filepath.Join(tmpDir, "b"), "b.go", `package b

import "example.com/z"

var _ = z.W
`)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: the walk must stop immediately.

	graph, edges, err := BuildImportGraphContext(ctx, tmpDir)
	if err != nil {
		t.Fatalf("expected no error on cancellation (partial results), got %v", err)
	}
	// With an already-cancelled context, the walk aborts before collecting edges.
	if len(edges) != 0 {
		t.Errorf("expected 0 edges when pre-cancelled, got %d", len(edges))
	}
	if graph == nil {
		t.Error("expected non-nil graph map even when cancelled")
	}
}

func TestBuildImportGraphContext_NotCancelledMatchesBuildImportGraph(t *testing.T) {
	tmpDir := t.TempDir()
	createGoFile(t, filepath.Join(tmpDir, "a"), "a.go", `package a

import "example.com/x"

var _ = x.Y
`)

	_, edgesCtx, err := BuildImportGraphContext(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(edgesCtx) != len(edges) {
		t.Errorf("ctx edges = %d, plain edges = %d; want equal", len(edgesCtx), len(edges))
	}
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}
}
