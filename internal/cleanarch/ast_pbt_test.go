package cleanarch

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: cleanarch, Property 10: Import graph completeness
// For any generated set of Go source files, every non-stdlib import declared in a
// file must appear both as an ImportEdge and in the ImportGraph for that package.
func TestProperty_ImportGraphCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp("", "cleanarch-pbt-*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(root)

		numPkgs := rapid.IntRange(1, 4).Draw(t, "numPkgs")

		// A pool of distinct external import "leaf" names. Prefixed with a
		// dotted domain below so they are never filtered as stdlib.
		importPool := rapid.SliceOfNDistinct(
			rapid.StringMatching(`[a-z]{1,6}`),
			1, 8,
			func(s string) string { return s },
		).Draw(t, "importPool")

		// pkgName -> the set of imports we wrote into that package.
		expected := make(map[string][]string)

		for p := 0; p < numPkgs; p++ {
			pkgName := "pkg" + strconv.Itoa(p)
			pkgDir := filepath.Join(root, pkgName)

			var imps []string
			for _, leaf := range importPool {
				if rapid.Bool().Draw(t, "pick_"+leaf) {
					imps = append(imps, "example.com/"+leaf)
				}
			}

			var b strings.Builder
			b.WriteString("package " + pkgName + "\n\n")
			if len(imps) > 0 {
				b.WriteString("import (\n")
				for _, ip := range imps {
					b.WriteString("\t\"" + ip + "\"\n")
				}
				b.WriteString(")\n")
			}

			writeGoFileRapid(t, pkgDir, "file.go", b.String())
			expected[pkgName] = imps
		}

		graph, edges, err := BuildImportGraph(root)
		if err != nil {
			t.Fatalf("BuildImportGraph: %v", err)
		}

		for pkg, imps := range expected {
			for _, ip := range imps {
				// Must appear in the graph adjacency list.
				if !containsString(graph[pkg], ip) {
					t.Errorf("graph[%q] missing import %q (graph=%v)", pkg, ip, graph[pkg])
				}
				// Must appear as a concrete edge with correct provenance.
				found := false
				for _, e := range edges {
					if e.FromPkg == pkg && e.ImportPath == ip {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no edge found for pkg=%q import=%q", pkg, ip)
				}
			}
		}
	})
}

// writeGoFileRapid writes a Go source file under dir within a property test.
// Writing temp fixtures from a test is unrelated to the module's read-only
// analysis guarantee, which concerns the production code paths only.
func writeGoFileRapid(t *rapid.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdirall %q: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writefile %q: %v", name, err)
	}
}
