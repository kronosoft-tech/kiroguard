package cleanarch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildImportGraph_MultiLang(t *testing.T) {
	tempDir := t.TempDir()

	// Create Go file
	goDir := filepath.Join(tempDir, "pkg_go")
	if err := os.MkdirAll(goDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	goFile := filepath.Join(goDir, "main.go")
	goContent := `package main
import "github.com/example/domain"
`
	if err := os.WriteFile(goFile, []byte(goContent), 0644); err != nil {
		t.Fatalf("failed to write go file: %v", err)
	}

	// Create Python file
	pyDir := filepath.Join(tempDir, "pkg_py")
	if err := os.MkdirAll(pyDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	pyFile := filepath.Join(pyDir, "app.py")
	pyContent := `import sys
import os
import requests
from domain.models import User
`
	if err := os.WriteFile(pyFile, []byte(pyContent), 0644); err != nil {
		t.Fatalf("failed to write python file: %v", err)
	}

	// Create TS file
	tsDir := filepath.Join(tempDir, "pkg_ts")
	if err := os.MkdirAll(tsDir, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	tsFile := filepath.Join(tsDir, "service.ts")
	tsContent := `import fs from 'fs';
import { UserRepo } from '../domain/repository';
const axios = require('axios');
`
	if err := os.WriteFile(tsFile, []byte(tsContent), 0644); err != nil {
		t.Fatalf("failed to write ts file: %v", err)
	}

	graph, edges, err := BuildImportGraph(tempDir)
	if err != nil {
		t.Fatalf("BuildImportGraph failed: %v", err)
	}

	if len(graph) < 3 {
		t.Errorf("expected at least 3 packages in graph, got %d", len(graph))
	}

	// Verify Python import extracted (requests, domain.models) and stdlib ignored (sys, os)
	pyEdges := 0
	tsEdges := 0
	for _, edge := range edges {
		if edge.FromPkg == "pkg_py" {
			pyEdges++
			if edge.ImportPath == "sys" || edge.ImportPath == "os" {
				t.Errorf("expected stdlib 'sys'/'os' to be ignored in Python imports")
			}
		}
		if edge.FromPkg == "pkg_ts" {
			tsEdges++
			if edge.ImportPath == "fs" {
				t.Errorf("expected Node stdlib 'fs' to be ignored in TS imports")
			}
		}
	}

	if pyEdges == 0 {
		t.Errorf("expected Python non-stdlib import edges, got 0")
	}
	if tsEdges == 0 {
		t.Errorf("expected TS non-stdlib import edges, got 0")
	}
}
