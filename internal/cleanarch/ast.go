// Package cleanarch implements AI-powered architecture linting using AST analysis.
package cleanarch

import (
	"bufio"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
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

// Ignored directory names for walking codebase trees.
var ignoredDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".git":         true,
	".venv":        true,
	"venv":         true,
	"__pycache__":  true,
	"dist":         true,
	"build":        true,
	".next":        true,
	"coverage":     true,
}

// Python standard library top-level modules.
var pythonStdLibModules = map[string]bool{
	"sys": true, "os": true, "re": true, "json": true, "math": true,
	"typing": true, "datetime": true, "time": true, "collections": true,
	"functools": true, "itertools": true, "pathlib": true, "unittest": true,
	"logging": true, "random": true, "string": true, "dataclasses": true,
	"enum": true, "abc": true, "asyncio": true, "hashlib": true,
	"base64": true, "subprocess": true, "io": true, "copy": true,
	"traceback": true, "contextlib": true, "argparse": true, "inspect": true,
	"socket": true, "struct": true, "urllib": true, "http": true,
	"threading": true, "multiprocessing": true, "shutil": true, "tempfile": true,
	"glob": true, "platform": true, "uuid": true, "signal": true, "warnings": true,
}

// Node.js standard library built-in modules.
var nodeStdLibModules = map[string]bool{
	"fs": true, "path": true, "http": true, "https": true, "events": true,
	"util": true, "os": true, "crypto": true, "stream": true, "child_process": true,
	"url": true, "querystring": true, "buffer": true, "zlib": true, "net": true,
	"tls": true, "dns": true, "readline": true, "assert": true, "console": true,
	"process": true, "timers": true, "cluster": true, "dgram": true,
}

// BuildImportGraph recursively parses all supported source files (Go, Python, JS/TS) in dir
// and builds a directed import graph.
func BuildImportGraph(dir string) (ImportGraph, []ImportEdge, error) {
	return BuildImportGraphContext(context.Background(), dir)
}

// BuildImportGraphContext is the context-aware variant of BuildImportGraph.
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

		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		if info.IsDir() {
			if ignoredDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		fileEdges, pkgPath, shouldProcess := extractFileImports(path, absDir)
		if !shouldProcess {
			return nil
		}

		for _, edge := range fileEdges {
			edges = append(edges, edge)
			if !containsString(graph[pkgPath], edge.ImportPath) {
				graph[pkgPath] = append(graph[pkgPath], edge.ImportPath)
			}
		}

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

// extractFileImports parses Go, Python, or JS/TS files to extract import edges.
func extractFileImports(filePath, absRoot string) ([]ImportEdge, string, bool) {
	relPath, err := filepath.Rel(absRoot, filepath.Dir(filePath))
	if err != nil {
		return nil, "", false
	}
	pkgPath := filepath.ToSlash(relPath)
	if pkgPath == "" {
		pkgPath = "."
	}

	relFilePath, err := filepath.Rel(absRoot, filePath)
	if err != nil {
		return nil, "", false
	}
	relFilePath = filepath.ToSlash(relFilePath)

	baseName := filepath.Base(filePath)

	if strings.HasSuffix(baseName, ".go") {
		if strings.HasSuffix(baseName, "_test.go") {
			return nil, "", false
		}
		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, filePath, nil, parser.ImportsOnly)
		if parseErr != nil {
			return nil, "", false
		}
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
		return edges, pkgPath, true
	}

	if strings.HasSuffix(baseName, ".py") {
		if strings.HasSuffix(baseName, "_test.py") || strings.HasPrefix(baseName, "test_") {
			return nil, "", false
		}
		edges := parsePythonImports(filePath, relFilePath, pkgPath)
		return edges, pkgPath, true
	}

	if isJSTSSuffix(baseName) {
		if isTestJSTSFile(baseName) {
			return nil, "", false
		}
		edges := parseJSImports(filePath, relFilePath, pkgPath)
		return edges, pkgPath, true
	}

	return nil, "", false
}

func isJSTSSuffix(name string) bool {
	suffixes := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func isTestJSTSFile(name string) bool {
	return strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") || strings.HasSuffix(name, "_test.ts") || strings.HasSuffix(name, "_test.js")
}

// Regex patterns for Python import parsing.
var (
	rePyFromImport = regexp.MustCompile(`^\s*from\s+([\w\.]+)\s+import`)
	rePyImport     = regexp.MustCompile(`^\s*import\s+([\w\.,\s]+)`)
)

func parsePythonImports(filePath, relFilePath, pkgPath string) []ImportEdge {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var edges []ImportEdge
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if match := rePyFromImport.FindStringSubmatch(line); len(match) > 1 {
			imp := match[1]
			topMod := strings.Split(imp, ".")[0]
			if !pythonStdLibModules[topMod] && imp != "" {
				edges = append(edges, ImportEdge{
					FromFile:   relFilePath,
					FromPkg:    pkgPath,
					ImportPath: imp,
					LineNumber: lineNum,
				})
			}
			continue
		}

		if match := rePyImport.FindStringSubmatch(line); len(match) > 1 {
			items := strings.Split(match[1], ",")
			for _, item := range items {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				parts := strings.Fields(item)
				if len(parts) > 0 {
					imp := parts[0]
					topMod := strings.Split(imp, ".")[0]
					if !pythonStdLibModules[topMod] {
						edges = append(edges, ImportEdge{
							FromFile:   relFilePath,
							FromPkg:    pkgPath,
							ImportPath: imp,
							LineNumber: lineNum,
						})
					}
				}
			}
		}
	}

	return edges
}

// Regex patterns for JS/TS import parsing.
var (
	reJSImportFrom    = regexp.MustCompile(`(?:import|export)\s+(?:[\s\w{},*$'"]+?\s+from\s+)?['"]([^'"]+)['"]`)
	reJSRequire       = regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	reJSDynamicImport = regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`)
)

func parseJSImports(filePath, relFilePath, pkgPath string) []ImportEdge {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var edges []ImportEdge
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		matches := reJSImportFrom.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) > 1 && m[1] != "" {
				imp := m[1]
				if !isNodeStdLib(imp) {
					edges = append(edges, ImportEdge{
						FromFile:   relFilePath,
						FromPkg:    pkgPath,
						ImportPath: imp,
						LineNumber: lineNum,
					})
				}
			}
		}

		reqMatches := reJSRequire.FindAllStringSubmatch(line, -1)
		for _, m := range reqMatches {
			if len(m) > 1 && m[1] != "" {
				imp := m[1]
				if !isNodeStdLib(imp) {
					edges = append(edges, ImportEdge{
						FromFile:   relFilePath,
						FromPkg:    pkgPath,
						ImportPath: imp,
						LineNumber: lineNum,
					})
				}
			}
		}

		dynMatches := reJSDynamicImport.FindAllStringSubmatch(line, -1)
		for _, m := range dynMatches {
			if len(m) > 1 && m[1] != "" {
				imp := m[1]
				if !isNodeStdLib(imp) {
					edges = append(edges, ImportEdge{
						FromFile:   relFilePath,
						FromPkg:    pkgPath,
						ImportPath: imp,
						LineNumber: lineNum,
					})
				}
			}
		}
	}

	return edges
}

func isNodeStdLib(imp string) bool {
	if strings.HasPrefix(imp, ".") || strings.HasPrefix(imp, "/") || strings.HasPrefix(imp, "@/") {
		return false
	}
	clean := strings.TrimPrefix(imp, "node:")
	first := strings.Split(clean, "/")[0]
	return nodeStdLibModules[first]
}

// isStdLibImport returns true if the Go import path looks like a standard library import.
func isStdLibImport(importPath string) bool {
	if strings.HasPrefix(importPath, ".") {
		return false
	}
	firstElement := importPath
	if idx := strings.Index(importPath, "/"); idx != -1 {
		firstElement = importPath[:idx]
	}
	return !strings.Contains(firstElement, ".")
}

// ParseFileImports parses a single file (Go, Python, JS/TS) and returns the import edges found in it.
func ParseFileImports(filePath string, rootDir string) ([]ImportEdge, error) {
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}

	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return nil, err
	}

	edges, _, _ := extractFileImports(absFile, absRoot)
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

