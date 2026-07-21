package cleanarch

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// helper to create a Go file in the given directory
func createGoFile(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildImportGraph_MultiplePkgsWithDeps(t *testing.T) {
	tmpDir := t.TempDir()

	// Create package "domain"
	createGoFile(t, filepath.Join(tmpDir, "domain"), "model.go", `package domain

import "github.com/example/shared"

type User struct{}
var _ = shared.Version
`)

	// Create package "infrastructure"
	createGoFile(t, filepath.Join(tmpDir, "infrastructure"), "repo.go", `package infrastructure

import (
	"github.com/example/shared"
	"github.com/example/project/domain"
)

var _ = shared.Version
var _ = domain.User{}
`)

	// Create package "shared" (no external deps)
	createGoFile(t, filepath.Join(tmpDir, "shared"), "utils.go", `package shared

var Version = "1.0"
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// Verify graph keys exist
	if _, ok := graph["domain"]; !ok {
		t.Error("expected 'domain' package in graph")
	}
	if _, ok := graph["infrastructure"]; !ok {
		t.Error("expected 'infrastructure' package in graph")
	}
	if _, ok := graph["shared"]; !ok {
		t.Error("expected 'shared' package in graph")
	}

	// Verify domain imports
	domainImports := graph["domain"]
	if len(domainImports) != 1 || domainImports[0] != "github.com/example/shared" {
		t.Errorf("domain imports = %v, want [github.com/example/shared]", domainImports)
	}

	// Verify infrastructure imports (2 external imports)
	infraImports := graph["infrastructure"]
	sort.Strings(infraImports)
	if len(infraImports) != 2 {
		t.Errorf("infrastructure imports count = %d, want 2", len(infraImports))
	}
	expected := []string{"github.com/example/project/domain", "github.com/example/shared"}
	sort.Strings(expected)
	for i, exp := range expected {
		if i < len(infraImports) && infraImports[i] != exp {
			t.Errorf("infrastructure import[%d] = %q, want %q", i, infraImports[i], exp)
		}
	}

	// Verify shared has no external imports
	if len(graph["shared"]) != 0 {
		t.Errorf("shared imports = %v, want []", graph["shared"])
	}

	// Verify edges contain expected entries
	if len(edges) != 3 {
		t.Errorf("edges count = %d, want 3", len(edges))
	}

	// Verify edge details
	foundDomainEdge := false
	for _, e := range edges {
		if e.FromPkg == "domain" && e.ImportPath == "github.com/example/shared" {
			foundDomainEdge = true
			if e.FromFile != "domain/model.go" {
				t.Errorf("domain edge FromFile = %q, want %q", e.FromFile, "domain/model.go")
			}
			if e.LineNumber <= 0 {
				t.Errorf("domain edge LineNumber = %d, want > 0", e.LineNumber)
			}
		}
	}
	if !foundDomainEdge {
		t.Error("expected edge from domain to github.com/example/shared")
	}
}

func TestBuildImportGraph_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	if len(graph) != 0 {
		t.Errorf("graph should be empty for empty directory, got: %v", graph)
	}
	if len(edges) != 0 {
		t.Errorf("edges should be empty for empty directory, got: %v", edges)
	}
}

func TestBuildImportGraph_SkipsTestFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a normal file with an external import
	createGoFile(t, tmpDir, "main.go", `package main

import "github.com/example/lib"

var _ = lib.Do
`)

	// Create a test file with different imports
	createGoFile(t, tmpDir, "main_test.go", `package main

import (
	"testing"
	"github.com/example/testutil"
)

func TestSomething(t *testing.T) {
	_ = testutil.Helper
}
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// Only the main.go import should be present
	rootImports := graph["."]
	if len(rootImports) != 1 {
		t.Errorf("expected 1 import in root package, got %d: %v", len(rootImports), rootImports)
	}
	if len(rootImports) > 0 && rootImports[0] != "github.com/example/lib" {
		t.Errorf("root import = %q, want %q", rootImports[0], "github.com/example/lib")
	}

	// Edges should not include the test file import
	for _, e := range edges {
		if e.ImportPath == "github.com/example/testutil" {
			t.Error("test file import should not appear in edges")
		}
	}
}

func TestBuildImportGraph_SkipsVendorDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file in the root
	createGoFile(t, tmpDir, "main.go", `package main

import "github.com/example/app"

var _ = app.Run
`)

	// Create a file in vendor that should be skipped
	createGoFile(t, filepath.Join(tmpDir, "vendor", "github.com", "example", "vendored"), "lib.go",
		`package vendored

import "github.com/example/internal"

var _ = internal.X
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// Only root package should be in graph
	if _, ok := graph["vendor/github.com/example/vendored"]; ok {
		t.Error("vendor package should not appear in graph")
	}

	// Edges should not include vendor file imports
	for _, e := range edges {
		if e.ImportPath == "github.com/example/internal" {
			t.Error("vendor file import should not appear in edges")
		}
	}

	// Root imports should still work
	if len(graph["."]) != 1 {
		t.Errorf("root imports = %v, want [github.com/example/app]", graph["."])
	}
	if len(edges) != 1 {
		t.Errorf("edges count = %d, want 1", len(edges))
	}
}

func TestBuildImportGraph_SkipsStdlib(t *testing.T) {
	tmpDir := t.TempDir()

	createGoFile(t, tmpDir, "main.go", `package main

import (
	"fmt"
	"os"
	"net/http"
	"github.com/example/mylib"
)

func main() {
	fmt.Println(os.Args)
	_ = http.DefaultClient
	_ = mylib.Do
}
`)

	graph, _, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// Only the external import should appear
	rootImports := graph["."]
	if len(rootImports) != 1 {
		t.Errorf("expected 1 non-stdlib import, got %d: %v", len(rootImports), rootImports)
	}
	if len(rootImports) > 0 && rootImports[0] != "github.com/example/mylib" {
		t.Errorf("import = %q, want %q", rootImports[0], "github.com/example/mylib")
	}
}

func TestBuildImportGraph_NestedPackages(t *testing.T) {
	tmpDir := t.TempDir()

	createGoFile(t, filepath.Join(tmpDir, "pkg", "sub", "deep"), "deep.go", `package deep

import "github.com/example/external"

var _ = external.X
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	pkgPath := "pkg/sub/deep"
	if _, ok := graph[pkgPath]; !ok {
		t.Errorf("expected %q in graph, keys: %v", pkgPath, graphKeys(graph))
	}

	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].FromPkg != pkgPath {
		t.Errorf("edge FromPkg = %q, want %q", edges[0].FromPkg, pkgPath)
	}
	if edges[0].FromFile != "pkg/sub/deep/deep.go" {
		t.Errorf("edge FromFile = %q, want %q", edges[0].FromFile, "pkg/sub/deep/deep.go")
	}
}

func TestBuildImportGraph_OnlyTestFilesDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Directory with only test files
	createGoFile(t, filepath.Join(tmpDir, "tests"), "handler_test.go", `package tests

import (
	"testing"
	"github.com/example/something"
)

func TestX(t *testing.T) { _ = something.X }
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// No packages should appear since all files are test files
	if len(graph) != 0 {
		t.Errorf("graph should be empty when only test files exist, got: %v", graph)
	}
	if len(edges) != 0 {
		t.Errorf("edges should be empty when only test files exist, got: %v", edges)
	}
}

func TestBuildImportGraph_DuplicateImportsDeduped(t *testing.T) {
	tmpDir := t.TempDir()

	// Two files in same package importing same external package
	createGoFile(t, filepath.Join(tmpDir, "svc"), "a.go", `package svc

import "github.com/example/shared"

var _ = shared.A
`)
	createGoFile(t, filepath.Join(tmpDir, "svc"), "b.go", `package svc

import "github.com/example/shared"

var _ = shared.B
`)

	graph, edges, err := BuildImportGraph(tmpDir)
	if err != nil {
		t.Fatalf("BuildImportGraph() error: %v", err)
	}

	// Graph should deduplicate at the package level
	svcImports := graph["svc"]
	if len(svcImports) != 1 {
		t.Errorf("expected 1 deduplicated import in graph, got %d: %v", len(svcImports), svcImports)
	}

	// But edges should have one per file
	if len(edges) != 2 {
		t.Errorf("expected 2 edges (one per file), got %d", len(edges))
	}
}

func TestIsStdLibImport(t *testing.T) {
	tests := []struct {
		importPath string
		isStdLib   bool
	}{
		{"fmt", true},
		{"os", true},
		{"net/http", true},
		{"encoding/json", true},
		{"go/ast", true},
		{"go/parser", true},
		{"github.com/example/lib", false},
		{"golang.org/x/tools", false},
		{"example.com/pkg", false},
		{"pgregory.net/rapid", false},
		{"./relative", false},
		{"../parent", false},
	}

	for _, tt := range tests {
		got := isStdLibImport(tt.importPath)
		if got != tt.isStdLib {
			t.Errorf("isStdLibImport(%q) = %v, want %v", tt.importPath, got, tt.isStdLib)
		}
	}
}

func TestParseFileImports(t *testing.T) {
	tmpDir := t.TempDir()

	createGoFile(t, tmpDir, "main.go", `package main

import (
	"fmt"
	"github.com/example/alpha"
	"github.com/example/beta"
)

func main() {
	fmt.Println(alpha.X, beta.Y)
}
`)

	edges, err := ParseFileImports(filepath.Join(tmpDir, "main.go"), tmpDir)
	if err != nil {
		t.Fatalf("ParseFileImports() error: %v", err)
	}

	if len(edges) != 2 {
		t.Fatalf("expected 2 edges, got %d: %v", len(edges), edges)
	}

	// Verify both external imports are captured
	importPaths := make(map[string]bool)
	for _, e := range edges {
		importPaths[e.ImportPath] = true
		if e.FromPkg != "." {
			t.Errorf("FromPkg = %q, want '.'", e.FromPkg)
		}
		if e.FromFile != "main.go" {
			t.Errorf("FromFile = %q, want 'main.go'", e.FromFile)
		}
	}
	if !importPaths["github.com/example/alpha"] {
		t.Error("missing import github.com/example/alpha")
	}
	if !importPaths["github.com/example/beta"] {
		t.Error("missing import github.com/example/beta")
	}
}

func TestBuildImportGraph_NonexistentDir(t *testing.T) {
	_, _, err := BuildImportGraph("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

// graphKeys returns the keys of an ImportGraph for debugging.
func graphKeys(g ImportGraph) []string {
	var keys []string
	for k := range g {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
