package cleanarch

import (
	"context"
	"fmt"
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

// ============================================================================
// JavaScript/TypeScript Tests
// ============================================================================

func createJSFile(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildImportGraphJS_ES6Imports(t *testing.T) {
	tmpDir := t.TempDir()

	// Create package "services"
	createJSFile(t, filepath.Join(tmpDir, "services"), "user.ts", `import { UserRepository } from '../repositories/user';
import { Logger } from '../utils/logger';

export class UserService {
  constructor(private repo: UserRepository, private logger: Logger) {}
}
`)

	// Create package "repositories"
	createJSFile(t, filepath.Join(tmpDir, "repositories"), "user.ts", `import { PrismaClient } from '@prisma/client';

export class UserRepository {
  constructor(private prisma: PrismaClient) {}
}
`)

	// Create package "utils"
	createJSFile(t, filepath.Join(tmpDir, "utils"), "logger.ts", `export class Logger {
  log(message: string) { console.log(message); }
}
`)

	graph, edges, err := BuildImportGraphJS(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that graph has all packages
	packages := graphKeys(graph)
	expectedPkgs := []string{"repositories", "services", "utils"}
	if len(packages) != len(expectedPkgs) {
		t.Errorf("expected %d packages, got %d: %v", len(expectedPkgs), len(packages), packages)
	}

	// Check that edges were created
	if len(edges) == 0 {
		t.Error("expected at least one import edge")
	}

	// Check specific imports
	servicesImports := graph["services"]
	if !containsString(servicesImports, "../repositories/user") {
		t.Errorf("expected services to import ../repositories/user, got %v", servicesImports)
	}
	if !containsString(servicesImports, "../utils/logger") {
		t.Errorf("expected services to import ../utils/logger, got %v", servicesImports)
	}
}

func TestBuildImportGraphJS_RequireCalls(t *testing.T) {
	tmpDir := t.TempDir()

	createJSFile(t, tmpDir, "index.js", `const express = require('express');
const { User } = require('./models/user');
const config = require('../config');

const app = express();
`)

	graph, edges, err := BuildImportGraphJS(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that relative imports are captured
	rootImports := graph["."]
	if !containsString(rootImports, "./models/user") {
		t.Errorf("expected root to import ./models/user, got %v", rootImports)
	}
	if !containsString(rootImports, "../config") {
		t.Errorf("expected root to import ../config, got %v", rootImports)
	}

	// Check that external dependencies (express) are also captured
	if !containsString(rootImports, "express") {
		t.Errorf("expected root to import express, got %v", rootImports)
	}

	// Check edges - should have 3 imports (express, ./models/user, ../config)
	if len(edges) != 3 {
		t.Errorf("expected 3 edges, got %d", len(edges))
	}
}

func TestBuildImportGraphJS_SkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create node_modules directory
	createJSFile(t, filepath.Join(tmpDir, "node_modules", "lodash"), "index.js", `module.exports = {}`)
	createJSFile(t, tmpDir, "app.ts", `import { helper } from './helper';
export const app = helper();
`)

	graph, _, err := BuildImportGraphJS(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have root package, not node_modules
	packages := graphKeys(graph)
	if len(packages) != 1 {
		t.Errorf("expected 1 package (root only), got %d: %v", len(packages), packages)
	}
}

func TestIsJSFile(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"app.js", true},
		{"app.jsx", true},
		{"app.ts", true},
		{"app.tsx", true},
		{"app.mjs", true},
		{"app.cjs", true},
		{"app.go", false},
		{"app.py", false},
		{"app.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJSFile(tt.name); got != tt.expected {
				t.Errorf("isJSFile(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestIsJSStdLibImport(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"fs", true},
		{"path", true},
		{"http", true},
		{"./relative", false},
		{"../relative", false},
		{"express", false},
		{"@types/node", true},
		{"@prisma/client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJSStdLibImport(tt.name); got != tt.expected {
				t.Errorf("isJSStdLibImport(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestExtractJSImports(t *testing.T) {
	source := `import { foo } from 'bar';
import defaultExport from 'baz';
import * as ns from 'qux';
import 'side-effect';
const req = require('./local');
`

	edges := extractJSImports(source, "test.ts", ".")

	// Should have 4 imports (side-effect import counts)
	expectedImports := []string{"bar", "baz", "qux", "side-effect", "./local"}
	if len(edges) != len(expectedImports) {
		t.Errorf("expected %d edges, got %d", len(expectedImports), len(edges))
	}

	for i, imp := range expectedImports {
		if i < len(edges) && edges[i].ImportPath != imp {
			t.Errorf("expected import %d to be %q, got %q", i, imp, edges[i].ImportPath)
		}
	}
}

// ============================================================================
// Python Tests
// ============================================================================

func TestBuildImportGraphPython(t *testing.T) {
	tmpDir := t.TempDir()

	// Create Python files with imports
	createJSFile(t, filepath.Join(tmpDir, "services"), "__init__.py", "")
	createJSFile(t, filepath.Join(tmpDir, "services"), "user.py", `from repositories.user import UserRepository
from utils.logger import Logger

class UserService:
    def __init__(self):
        self.repo = UserRepository()
        self.logger = Logger()
`)

	createJSFile(t, filepath.Join(tmpDir, "repositories"), "__init__.py", "")
	createJSFile(t, filepath.Join(tmpDir, "repositories"), "user.py", `import sqlalchemy
from models import User

class UserRepository:
    def __init__(self):
        self.db = sqlalchemy.create_engine('sqlite:///db.sqlite')
`)

	createJSFile(t, filepath.Join(tmpDir, "utils"), "__init__.py", "")
	createJSFile(t, filepath.Join(tmpDir, "utils"), "logger.py", `class Logger:
    def log(self, message):
        print(message)
`)

	graph, edges, err := BuildImportGraphPythonContext(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that graph has packages
	packages := graphKeys(graph)
	if len(packages) < 2 {
		t.Errorf("expected at least 2 packages, got %d: %v", len(packages), packages)
	}

	// Check that edges were created
	if len(edges) == 0 {
		t.Error("expected at least one import edge")
	}

	// Check specific imports
	servicesImports := graph["services"]
	if !containsString(servicesImports, "repositories.user") {
		t.Errorf("expected services to import repositories.user, got %v", servicesImports)
	}
	if !containsString(servicesImports, "utils.logger") {
		t.Errorf("expected services to import utils.logger, got %v", servicesImports)
	}
}

func TestBuildImportGraphPython_SkipsBuiltinModules(t *testing.T) {
	tmpDir := t.TempDir()

	createJSFile(t, tmpDir, "app.py", `import os
import sys
from pathlib import Path
from models import User
`)

	_, edges, err := BuildImportGraphPythonContext(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have models import, not os/sys/pathlib
	for _, edge := range edges {
		if edge.ImportPath == "os" || edge.ImportPath == "sys" || edge.ImportPath == "pathlib" {
			t.Errorf("should not include Python stdlib import: %s", edge.ImportPath)
		}
	}

	if len(edges) != 1 {
		t.Errorf("expected 1 edge (models), got %d", len(edges))
	}
}

func TestIsPythonStdLibImport(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"os", true},
		{"sys", true},
		{"pathlib", true},
		{"flask", false},
		{"django", false},
		{"sqlalchemy", false},
		{".relative", false},
		{"mypackage.module", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPythonStdLibImport(tt.name); got != tt.expected {
				t.Errorf("isPythonStdLibImport(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Java Tests
// ============================================================================

func TestBuildImportGraphJava(t *testing.T) {
	tmpDir := t.TempDir()

	// Create Java files with imports
	createJSFile(t, filepath.Join(tmpDir, "com", "example", "services"), "UserService.java", `package com.example.services;

import com.example.repositories.UserRepository;
import com.example.utils.Logger;

public class UserService {
    private UserRepository repo;
    private Logger logger;
}
`)

	createJSFile(t, filepath.Join(tmpDir, "com", "example", "repositories"), "UserRepository.java", `package com.example.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.models.User;

public class UserRepository implements JpaRepository<User, Long> {
}
`)

	createJSFile(t, filepath.Join(tmpDir, "com", "example", "utils"), "Logger.java", `package com.example.utils;

public class Logger {
    public void log(String message) {
        System.out.println(message);
    }
}
`)

	graph, edges, err := BuildImportGraphJavaContext(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that graph has packages
	packages := graphKeys(graph)
	if len(packages) < 2 {
		t.Errorf("expected at least 2 packages, got %d: %v", len(packages), packages)
	}

	// Check that edges were created
	if len(edges) == 0 {
		t.Error("expected at least one import edge")
	}

	// Check specific imports
	servicesImports := graph["com/example/services"]
	if !containsString(servicesImports, "com.example.repositories.UserRepository") {
		t.Errorf("expected services to import com.example.repositories.UserRepository, got %v", servicesImports)
	}
	if !containsString(servicesImports, "com.example.utils.Logger") {
		t.Errorf("expected services to import com.example.utils.Logger, got %v", servicesImports)
	}
}

func TestBuildImportGraphJava_SkipsStdlib(t *testing.T) {
	tmpDir := t.TempDir()

	createJSFile(t, tmpDir, "App.java", `package com.example;

import java.util.List;
import java.util.ArrayList;
import javax.sql.DataSource;
import com.example.models.User;

public class App {
}
`)

	_, edges, err := BuildImportGraphJavaContext(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have com.example.models.User import
	for _, edge := range edges {
		if edge.ImportPath == "java.util.List" || edge.ImportPath == "java.util.ArrayList" || edge.ImportPath == "javax.sql.DataSource" {
			t.Errorf("should not include Java stdlib import: %s", edge.ImportPath)
		}
	}

	if len(edges) != 1 {
		t.Errorf("expected 1 edge (com.example.models.User), got %d", len(edges))
	}
}

func TestIsJavaStdLibImport(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"java.util.List", true},
		{"java.sql.Connection", true},
		{"javax.servlet.http.HttpServletRequest", true},
		{"org.springframework.boot.SpringApplication", false},
		{"com.example.MyClass", false},
		{"io.jsonwebtoken.Jwts", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJavaStdLibImport(tt.name); got != tt.expected {
				t.Errorf("isJavaStdLibImport(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]int // extension -> count
		expected string
	}{
		{
			name:     "Go project",
			files:    map[string]int{".go": 10, ".py": 2},
			expected: "go",
		},
		{
			name:     "Python project",
			files:    map[string]int{".py": 20, ".go": 3},
			expected: "python",
		},
		{
			name:     "Java project",
			files:    map[string]int{".java": 15, ".py": 2},
			expected: "java",
		},
		{
			name:     "JavaScript project",
			files:    map[string]int{".js": 10, ".ts": 8, ".go": 2},
			expected: "js",
		},
		{
			name:     "Mixed project - Go wins",
			files:    map[string]int{".go": 5, ".py": 3, ".js": 2},
			expected: "go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			for ext, count := range tt.files {
				for i := 0; i < count; i++ {
					createJSFile(t, tmpDir, fmt.Sprintf("file%d%s", i, ext), "content")
				}
			}

			got := detectLanguage(tmpDir)
			if got != tt.expected {
				t.Errorf("detectLanguage() = %v, want %v", got, tt.expected)
			}
		})
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
