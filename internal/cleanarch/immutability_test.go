package cleanarch

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: cleanarch, Property 12: Source code immutability in Clean-Arch
// For any directory analyzed by BuildImportGraph, the set of files and their
// contents must be byte-for-byte identical before and after the analysis run.
func TestProperty_SourceImmutability(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		root, err := os.MkdirTemp("", "cleanarch-immut-*")
		if err != nil {
			t.Fatalf("mkdirtemp: %v", err)
		}
		defer os.RemoveAll(root)

		numFiles := rapid.IntRange(1, 6).Draw(t, "numFiles")
		for i := 0; i < numFiles; i++ {
			content := generateRandomGoSource(t, i)
			dir := filepath.Join(root, "pkg"+strconv.Itoa(i))
			writeGoFileRapid(t, dir, "file.go", content)
		}

		before := hashDir(t, root)

		if _, _, err := BuildImportGraph(root); err != nil {
			t.Fatalf("BuildImportGraph: %v", err)
		}

		after := hashDir(t, root)

		if len(before) != len(after) {
			t.Fatalf("file set changed: %d files before, %d after", len(before), len(after))
		}
		for path, h := range before {
			ah, ok := after[path]
			if !ok {
				t.Errorf("file %q disappeared after analysis", path)
				continue
			}
			if ah != h {
				t.Errorf("file %q content changed: before %x, after %x", path, h, ah)
			}
		}
	})
}

// generateRandomGoSource builds a syntactically plausible Go file with a random
// mix of stdlib and external imports. Even if parsing fails, immutability must
// hold, so the exact validity of the source is not important.
func generateRandomGoSource(t *rapid.T, idx int) string {
	importPool := rapid.SliceOfNDistinct(
		rapid.SampledFrom([]string{
			"fmt", "os", "strings", "net/http",
			"example.com/foo", "github.com/a/b", "gitlab.com/x/y",
		}),
		0, 5,
		func(s string) string { return s },
	).Draw(t, "imports")

	var b strings.Builder
	b.WriteString("package pkg" + strconv.Itoa(idx) + "\n\n")
	if len(importPool) > 0 {
		b.WriteString("import (\n")
		for _, ip := range importPool {
			b.WriteString("\t\"" + ip + "\"\n")
		}
		b.WriteString(")\n")
	}
	return b.String()
}

// hashDir walks root and returns a map of relative file path -> sha256 of its
// contents. It only reads files; it never mutates them.
func hashDir(t *rapid.T, root string) map[string][32]byte {
	t.Helper()
	hashes := make(map[string][32]byte)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		hashes[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatalf("hashDir walk: %v", err)
	}
	return hashes
}
