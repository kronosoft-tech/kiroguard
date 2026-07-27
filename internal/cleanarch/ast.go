// Package cleanarch implements AI-powered architecture linting using AST analysis.
package cleanarch

import (
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

// ============================================================================
// JavaScript/TypeScript Support
// ============================================================================

// jsImportPattern matches ES6 import statements
// import { foo } from 'bar';
// import foo from 'bar';
// import * as foo from 'bar';
// import 'bar'; (side-effect import)
var jsImportPattern = regexp.MustCompile(`^import\s+(?:(?:\{[^}]*\}|[\w$*]+\s+(?:as\s+\w+)?|[\w$]+)\s+from\s+)?['"]([^'"]+)['"]`)

// jsRequirePattern matches CommonJS require calls
// const foo = require('bar');
// const { foo } = require('bar');
// require('bar');
var jsRequirePattern = regexp.MustCompile(`(?:require\s*\(\s*['"]([^'"]+)['"]\s*\))`)

// jsExportPattern matches export statements (for future use)
var jsExportPattern = regexp.MustCompile(`^export\s+(?:default\s+)?(?:function|class|const|let|var|interface|type)\s+\w+`)

// jsNodeBuiltins contains Node.js standard library modules
var jsNodeBuiltins = map[string]bool{
	"assert": true, "buffer": true, "child_process": true, "cluster": true,
	"console": true, "constants": true, "crypto": true, "dgram": true,
	"dns": true, "domain": true, "events": true, "fs": true,
	"http": true, "https": true, "module": true, "net": true,
	"os": true, "path": true, "process": true, "punycode": true,
	"querystring": true, "readline": true, "repl": true, "stream": true,
	"string_decoder": true, "sys": true, "timers": true, "tls": true,
	"tty": true, "url": true, "util": true, "v8": true,
	"vm": true, "worker_threads": true, "zlib": true,
}

// BuildImportGraphJS builds an import graph for JavaScript/TypeScript files.
func BuildImportGraphJS(dir string) (ImportGraph, []ImportEdge, error) {
	return BuildImportGraphJSContext(context.Background(), dir)
}

// BuildImportGraphJSContext is the context-aware variant of BuildImportGraphJS.
func BuildImportGraphJSContext(ctx context.Context, dir string) (ImportGraph, []ImportEdge, error) {
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

		// Stop the walk if the context is done
		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		// Skip vendor and node_modules directories
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == ".git") {
			return filepath.SkipDir
		}

		// Only process JS/TS files
		if info.IsDir() {
			return nil
		}
		if !isJSFile(info.Name()) {
			return nil
		}

		// Read file content
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		// Determine relative package path
		relPath, relErr := filepath.Rel(absDir, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		pkgPath := filepath.ToSlash(relPath)
		if pkgPath == "" {
			pkgPath = "."
		}

		// Relative file path
		relFilePath, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return relErr
		}
		relFilePath = filepath.ToSlash(relFilePath)

		// Extract imports from file content
		fileEdges := extractJSImports(string(content), relFilePath, pkgPath)
		edges = append(edges, fileEdges...)

		// Add to graph
		for _, edge := range fileEdges {
			if !containsString(graph[pkgPath], edge.ImportPath) {
				graph[pkgPath] = append(graph[pkgPath], edge.ImportPath)
			}
		}

		// Ensure the package appears in the graph
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

// isJSFile checks if a filename is a JavaScript or TypeScript file
func isJSFile(name string) bool {
	jsExtensions := []string{
		".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
	}
	for _, ext := range jsExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// extractJSImports extracts import statements from JS/TS source code
func extractJSImports(content, filePath, pkgPath string) []ImportEdge {
	var edges []ImportEdge
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Check for ES6 imports
		if matches := jsImportPattern.FindStringSubmatch(trimmed); matches != nil {
			importPath := matches[1]
			if !isJSStdLibImport(importPath) {
				edges = append(edges, ImportEdge{
					FromFile:   filePath,
					FromPkg:    pkgPath,
					ImportPath: importPath,
					LineNumber: lineNum + 1,
				})
			}
		}

		// Check for require() calls
		if matches := jsRequirePattern.FindStringSubmatch(trimmed); matches != nil {
			importPath := matches[1]
			if !isJSStdLibImport(importPath) {
				edges = append(edges, ImportEdge{
					FromFile:   filePath,
					FromPkg:    pkgPath,
					ImportPath: importPath,
					LineNumber: lineNum + 1,
				})
			}
		}
	}

	return edges
}

// isJSStdLibImport checks if an import path is a Node.js built-in module
func isJSStdLibImport(importPath string) bool {
	// Relative imports are not stdlib
	if strings.HasPrefix(importPath, ".") {
		return false
	}

	// Check for scoped packages (e.g., @types/node)
	if strings.HasPrefix(importPath, "@") {
		parts := strings.Split(importPath, "/")
		if len(parts) >= 2 {
			return parts[0] == "@types" && parts[1] == "node"
		}
		return false
	}

	// Check for built-in modules
	moduleName := importPath
	if idx := strings.Index(importPath, "/"); idx != -1 {
		moduleName = importPath[:idx]
	}

	return jsNodeBuiltins[moduleName]
}

// ============================================================================
// Language Detection
// ============================================================================

// detectLanguage scans a directory to determine the dominant programming language.
func detectLanguage(dir string) string {
	extCounts := map[string]int{
		".go":  0,
		".js":  0, ".jsx": 0, ".ts": 0, ".tsx": 0, ".mjs": 0, ".cjs": 0,
		".py":  0,
		".java": 0,
	}

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip vendor/node_modules
		if strings.Contains(path, "vendor") || strings.Contains(path, "node_modules") {
			return filepath.SkipDir
		}
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := extCounts[ext]; ok {
			extCounts[ext]++
		}
		return nil
	})

	// Determine dominant language
	goCount := extCounts[".go"]
	jsCount := extCounts[".js"] + extCounts[".jsx"] + extCounts[".ts"] + extCounts[".tsx"] + extCounts[".mjs"] + extCounts[".cjs"]
	pyCount := extCounts[".py"]
	javaCount := extCounts[".java"]

	maxCount := goCount
	lang := "go"

	if jsCount > maxCount {
		maxCount = jsCount
		lang = "js"
	}
	if pyCount > maxCount {
		maxCount = pyCount
		lang = "python"
	}
	if javaCount > maxCount {
		maxCount = javaCount
		lang = "java"
	}

	return lang
}

// ============================================================================
// Python Support
// ============================================================================

// pythonImportPattern matches Python import statements
// import foo
// import foo.bar
// from foo import bar
// from foo.bar import baz
var pythonImportPattern = regexp.MustCompile(`^(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)`)

// pythonBuiltinModules contains Python standard library modules
var pythonBuiltinModules = map[string]bool{
	"abc": true, "aifc": true, "argparse": true, "array": true,
	"ast": true, "asynchat": true, "asyncio": true, "asyncore": true,
	"atexit": true, "audioop": true, "base64": true, "bdb": true,
	"binascii": true, "binhex": true, "bisect": true, "builtins": true,
	"bz2": true, "calendar": true, "cgi": true, "cgitb": true,
	"chunk": true, "cmath": true, "cmd": true, "code": true,
	"codecs": true, "codeop": true, "collections": true, "colorsys": true,
	"compileall": true, "concurrent": true, "configparser": true, "contextlib": true,
	"contextvars": true, "copy": true, "copyreg": true, "cProfile": true,
	"crypt": true, "csv": true, "ctypes": true, "curses": true,
	"dataclasses": true, "datetime": true, "dbm": true, "decimal": true,
	"difflib": true, "dis": true, "distutils": true, "doctest": true,
	"email": true, "encodings": true, "enum": true, "errno": true,
	"faulthandler": true, "fcntl": true, "filecmp": true, "fileinput": true,
	"fnmatch": true, "fractions": true, "ftplib": true, "functools": true,
	"gc": true, "getopt": true, "getpass": true, "gettext": true,
	"glob": true, "graphlib": true, "grp": true, "gzip": true,
	"hashlib": true, "heapq": true, "hmac": true, "html": true,
	"http": true, "idlelib": true, "imaplib": true, "imghdr": true,
	"imp": true, "importlib": true, "inspect": true, "io": true,
	"ipaddress": true, "itertools": true, "json": true, "keyword": true,
	"lib2to3": true, "linecache": true, "locale": true, "logging": true,
	"lzma": true, "mailbox": true, "mailcap": true, "marshal": true,
	"math": true, "mimetypes": true, "mmap": true, "modulefinder": true,
	"multiprocessing": true, "netrc": true, "nis": true, "nntplib": true,
	"numbers": true, "operator": true, "optparse": true, "os": true,
	"ossaudiodev": true, "pathlib": true, "pdb": true, "pickle": true,
	"pickletools": true, "pipes": true, "pkgutil": true, "platform": true,
	"plistlib": true, "poplib": true, "posix": true, "posixpath": true,
	"pprint": true, "profile": true, "pstats": true, "pty": true,
	"pwd": true, "py_compile": true, "pyclbr": true, "pydoc": true,
	"queue": true, "quopri": true, "random": true, "re": true,
	"readline": true, "reprlib": true, "resource": true, "rlcompleter": true,
	"runpy": true, "sched": true, "secrets": true, "select": true,
	"selectors": true, "shelve": true, "shlex": true, "shutil": true,
	"signal": true, "site": true, "smtpd": true, "smtplib": true,
	"sndhdr": true, "socket": true, "socketserver": true, "sqlite3": true,
	"ssl": true, "stat": true, "statistics": true, "string": true,
	"struct": true, "subprocess": true, "sunau": true, "symtable": true,
	"sys": true, "sysconfig": true, "syslog": true, "tabnanny": true,
	"tarfile": true, "telnetlib": true, "tempfile": true, "termios": true,
	"textwrap": true, "threading": true, "time": true, "timeit": true,
	"tkinter": true, "token": true, "tokenize": true, "tomllib": true,
	"trace": true, "traceback": true, "tracemalloc": true, "tty": true,
	"turtle": true, "turtledemo": true, "types": true, "typing": true,
	"unicodedata": true, "unittest": true, "urllib": true, "uu": true,
	"uuid": true, "venv": true, "warnings": true, "wave": true,
	"weakref": true, "webbrowser": true, "winreg": true, "winsound": true,
	"wsgiref": true, "xdrlib": true, "xml": true, "xmlrpc": true,
	"zipapp": true, "zipfile": true, "zipimport": true, "zlib": true,
}

// BuildImportGraphPythonContext builds an import graph for Python files.
func BuildImportGraphPythonContext(ctx context.Context, dir string) (ImportGraph, []ImportEdge, error) {
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
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == ".git" || info.Name() == "__pycache__") {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".py") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		relPath, relErr := filepath.Rel(absDir, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		pkgPath := filepath.ToSlash(relPath)
		if pkgPath == "" {
			pkgPath = "."
		}

		relFilePath, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return relErr
		}
		relFilePath = filepath.ToSlash(relFilePath)

		fileEdges := extractPythonImports(string(content), relFilePath, pkgPath)
		edges = append(edges, fileEdges...)

		for _, edge := range fileEdges {
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

// extractPythonImports extracts import statements from Python source code
func extractPythonImports(content, filePath, pkgPath string) []ImportEdge {
	var edges []ImportEdge
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		if matches := pythonImportPattern.FindStringSubmatch(trimmed); matches != nil {
			var importPath string
			if matches[1] != "" {
				importPath = matches[1]
			} else {
				importPath = matches[2]
			}

			if !isPythonStdLibImport(importPath) {
				edges = append(edges, ImportEdge{
					FromFile:   filePath,
					FromPkg:    pkgPath,
					ImportPath: importPath,
					LineNumber: lineNum + 1,
				})
			}
		}
	}
	return edges
}

// isPythonStdLibImport checks if an import path is a Python built-in module
func isPythonStdLibImport(importPath string) bool {
	// Relative imports are not stdlib
	if strings.HasPrefix(importPath, ".") {
		return false
	}

	// Get the root module name
	moduleName := importPath
	if idx := strings.Index(importPath, "."); idx != -1 {
		moduleName = importPath[:idx]
	}

	return pythonBuiltinModules[moduleName]
}

// ============================================================================
// Java Support
// ============================================================================

// javaImportPattern matches Java import statements
// import java.util.List;
// import com.example.MyClass;
// import static org.junit.Assert.assertEquals;
var javaImportPattern = regexp.MustCompile(`^import\s+(?:static\s+)?([\w.]+);`)

// javaPackagePattern matches Java package declarations
var javaPackagePattern = regexp.MustCompile(`^package\s+([\w.]+);`)

// javaStdLibPackages contains Java standard library packages
var javaStdLibPackages = map[string]bool{
	"java": true, "javax": true, "jdk": true, "org.xml": true,
	"org.w3c": true, "org.ietf": true, "org.jcp": true,
}

// BuildImportGraphJavaContext builds an import graph for Java files.
func BuildImportGraphJavaContext(ctx context.Context, dir string) (ImportGraph, []ImportEdge, error) {
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
		if info.IsDir() && (info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == ".git" || info.Name() == "target" || info.Name() == "build") {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".java") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		relPath, relErr := filepath.Rel(absDir, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		pkgPath := filepath.ToSlash(relPath)
		if pkgPath == "" {
			pkgPath = "."
		}

		relFilePath, relErr := filepath.Rel(absDir, path)
		if relErr != nil {
			return relErr
		}
		relFilePath = filepath.ToSlash(relFilePath)

		fileEdges := extractJavaImports(string(content), relFilePath, pkgPath)
		edges = append(edges, fileEdges...)

		for _, edge := range fileEdges {
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

// extractJavaImports extracts import statements from Java source code
func extractJavaImports(content, filePath, pkgPath string) []ImportEdge {
	var edges []ImportEdge
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if matches := javaImportPattern.FindStringSubmatch(trimmed); matches != nil {
			importPath := matches[1]
			if !isJavaStdLibImport(importPath) {
				edges = append(edges, ImportEdge{
					FromFile:   filePath,
					FromPkg:    pkgPath,
					ImportPath: importPath,
					LineNumber: lineNum + 1,
				})
			}
		}
	}
	return edges
}

// isJavaStdLibImport checks if an import path is a Java built-in module
func isJavaStdLibImport(importPath string) bool {
	// Get the root package
	rootPkg := importPath
	if idx := strings.Index(importPath, "."); idx != -1 {
		rootPkg = importPath[:idx]
	}
	return javaStdLibPackages[rootPkg]
}
