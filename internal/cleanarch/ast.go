















// Package cleanarch implements AI-powered architecture linting using AST analysis.
package cleanarch

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// ImportGraph represents a directed graph of package import relationships.
// Each key is the package path (relative to the project root) and the value
// is a list of packages it imports.
type ImportGraph map[string][]string

// ImportEdge represents a single import relationship.
type ImportEdge struct {
	FromFile   string `json:"from_file"`
	FromPkg    string `json:"from_pkg"`
	ImportPath string `json:"import_path"`
	LineNumber int    `json:"line_number"`
}

// BuildImportGraph recursively parses all Go source files in the given directory
// and builds a directed import graph. It is equivalent to BuildImportGraphContext
// with a background (non-cancellable) context.
func BuildImportGraph(dir string) (ImportGraph, []ImportEdge, error) {
	return BuildImportGraphContext(context.Background(), dir)
}

// BuildImportGraphContext is the context-aware variant of BuildImportGraph.
// If ctx is cancelled or its deadline is exceeded during the directory walk,
// the walk stops early and the graph/edges collected so far are returned with a
// nil error (partial results). Callers can inspect ctx.Err() to detect truncation.
func BuildImportGraphContext(ctx context.Context, dir string) (ImportGraph, []ImportEdge, error) {
	graph := make(ImportGraph)
	var edges []ImportEdge

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, err
	}

	err = filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Stop the walk if the context is done, keeping partial results.
		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		// Skip vendor directories
		if info.IsDir() && info.Name() == "vendor" {
			return filepath.SkipDir
		}

		// Only process .go files, skip test files
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		// Parse the file
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			// Skip files that can't be parsed
			return nil
		}

		// Determine the relative package path from the root directory
		relPath, err := filepath.Rel(absDir, filepath.Dir(path))
		if err != nil {
			return err
		}
		// Normalize to forward slashes for consistency
		pkgPath := filepath.ToSlash(relPath)
		if pkgPath == "" {
			pkgPath = "."
		}

		// Relative file path for edge info
		relFilePath, err := filepath.Rel(absDir, path)
		if err != nil {
			return err
		}
		relFilePath = filepath.ToSlash(relFilePath)

		// Extract imports
		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)

			// Skip standard library imports (no dots in path and not a relative import)
			if isStdLibImport(importPath) {
				continue
			}

			// Record edge
			edge := ImportEdge{
				FromFile:   relFilePath,
				FromPkg:    pkgPath,
				ImportPath: importPath,
				LineNumber: fset.Position(imp.Pos()).Line,
			}
			edges = append(edges, edge)

			// Add to graph
			if !containsString(graph[pkgPath], importPath) {
				graph[pkgPath] = append(graph[pkgPath], importPath)
			}
		}

		// Ensure the package appears in the graph even if it has no non-stdlib imports
		if _, exists := graph[pkgPath]; !exists {
			graph[pkgPath] = []string{}
		}

		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return graph, edges, nil
}

// isStdLibImport returns true if the import path looks like a standard library import.
// Standard library imports don't contain dots in their path (e.g., "fmt", "os/exec").
// Paths with dots are assumed to be external or local module imports (e.g., "github.com/...", "example.com/...").
func isStdLibImport(importPath string) bool {
	// Relative imports are not stdlib
	if strings.HasPrefix(importPath, ".") {
		return false
	}
	// Standard library packages don't contain dots in the first path element
	firstElement := importPath
	if idx := strings.Index(importPath, "/"); idx != -1 {
		firstElement = importPath[:idx]
	}
	return !strings.Contains(firstElement, ".")
}

// ParseFileImports parses a single Go file and returns the import edges found in it.
// This is useful for analyzing individual files without walking a full directory.
func ParseFileImports(filePath string, rootDir string) ([]ImportEdge, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, absFile, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}

	relPath, err := filepath.Rel(absRoot, filepath.Dir(absFile))
	if err != nil {
		return nil, err
	}
	pkgPath := filepath.ToSlash(relPath)
	if pkgPath == "" {
		pkgPath = "."
	}

	relFilePath, err := filepath.Rel(absRoot, absFile)
	if err != nil {
		return nil, err
	}
	relFilePath = filepath.ToSlash(relFilePath)

	var edges []ImportEdge
	for _, imp := range f.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		if isStdLibImport(importPath) {
			continue
		}
		edges = append(edges, ImportEdge{
			FromFile:   relFilePath,
			FromPkg:    pkgPath,
			ImportPath: importPath,
			LineNumber: fset.Position(imp.Pos()).Line,
		})
	}
	return edges, nil
}

// containsString checks if a slice contains a specific string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// nodeImports extracts import paths from an AST file node (used internally).
func nodeImports(f *ast.File) []string {
	var imports []string
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		imports = append(imports, path)
	}
	return imports
}
