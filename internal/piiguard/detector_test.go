package piiguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanFiles_WithAWSKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const AWS_KEY = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalFindings == 0 {
		t.Fatal("expected findings")
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "aws_access_key" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("severity = %q, want critical", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("aws_access_key not found among %d findings", len(findings))
	}
}

func TestScanFiles_WithCreditCard(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
var cc = "4111-1111-1111-1111"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "credit_card" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("credit_card not found among %d findings", len(findings))
	}
}

func TestScanFiles_WithEmail(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main
// contact test@example.com for support
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	// Email in a comment should NOT be flagged (comment-only line)
	if len(findings) > 0 {
		t.Errorf("expected 0 findings on comment-only line, got %d", len(findings))
	}
}

func TestScanFiles_EmailInCode(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main
const email = "test@example.com"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "email" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("email not found among %d findings", len(findings))
	}
}

func TestScanFiles_WithPasswordField(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.json", `{
	"password": "supersecret123"
}`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "password_field" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("password_field not found among %d findings", len(findings))
	}
}

func TestScanFiles_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main_test.go", `package main
const key = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("expected 0 findings in test file, got %d", len(findings))
	}
}

func TestScanFiles_SkipsVendorDir(t *testing.T) {
	dir := t.TempDir()
	vendor := filepath.Join(dir, "vendor")
	os.MkdirAll(vendor, 0755)
	writeFile(t, vendor, "lib.go", `package lib
const key = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("expected 0 findings in vendor dir, got %d", len(findings))
	}
}

func TestScanFiles_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	os.MkdirAll(nm, 0755)
	writeFile(t, nm, "dep.js", `const key = "AKIA1234567890123456"`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) > 0 {
		t.Errorf("expected 0 findings in node_modules, got %d", len(findings))
	}
}

func TestScanFiles_SkipsBinaryFile(t *testing.T) {
	dir := t.TempDir()
	bin := writeFile(t, dir, "image.png", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00")
	info, _ := os.Stat(bin)
	if info.Size() > 0 {
		patterns := GetPatterns(nil)
		findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) > 0 {
			t.Errorf("expected 0 findings in binary file, got %d", len(findings))
		}
	}
}

func TestScanFiles_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if summary.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0", summary.FilesScanned)
	}
}

func TestScanFiles_NoFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main
func main() { println("hello") }
`)
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if summary.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", summary.FilesScanned)
	}
}

func TestScanFiles_Deduplicates(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const key1 = "AKIA1234567890123456"
const key2 = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range findings {
		if f.PatternType == "aws_access_key" {
			count++
		}
	}
	// Two lines with same key on each = 2 findings
	if count != 2 {
		t.Errorf("expected 2 aws_access_key findings, got %d", count)
	}
}

func TestScanFiles_EntropyFindings(t *testing.T) {
	dir := t.TempDir()
	// Use a string that doesn't match named patterns but has high entropy
	writeFile(t, dir, "config.go", `package main
const x = "X8kL1mN2oP4qR6sT8uV0wX2yZ4aB3dE5fG7hI9"
`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, true, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "high_entropy_string" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("high_entropy_string not found among %d findings", len(findings))
	}
}

func TestScanFiles_ThresholdFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `package main
const email = "test@example.com"
const key = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	// Should have both email (low) and aws_access_key (critical)
	if summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
	if summary.ByPatternType["email"] == 0 {
		t.Error("expected email finding")
	}
	if summary.ByPatternType["aws_access_key"] == 0 {
		t.Error("expected aws_access_key finding")
	}
}

func TestScanFiles_NonexistentDir(t *testing.T) {
	patterns := GetPatterns(nil)
	_, _, err := ScanFiles(context.Background(), "/nonexistent/path", patterns, false, 2*1024*1024)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestScanFiles_SkipsLockFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package-lock.json", `{"key": "AKIA1234567890123456"}`)
	writeFile(t, dir, "yarn.lock", "key: AKIA1234567890123456")
	writeFile(t, dir, "real.go", `package main
const key = "AKIA1234567890123456"
`)
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if summary.FilesScanned != 1 {
		t.Errorf("FilesScanned = %d, want 1", summary.FilesScanned)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding from real.go, got %d", len(findings))
	}
}

func TestScanFiles_FileOverMaxSize(t *testing.T) {
	dir := t.TempDir()
	// Create a file larger than 100 bytes max
	data := make([]byte, 200)
	for i := range data {
		data[i] = 'A'
	}
	writeFile(t, dir, "big.go", string(data))
	patterns := GetPatterns(nil)
	findings, summary, err := ScanFiles(context.Background(), dir, patterns, false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for oversized file, got %d", len(findings))
	}
	if summary.FilesSkipped != 1 {
		t.Errorf("FilesSkipped = %d, want 1", summary.FilesSkipped)
	}
}

func TestScanFiles_SSN(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "data.txt", `ssn: 123-45-6789`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "ssn" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ssn not found among %d findings", len(findings))
	}
}

func TestScanFiles_GitHubToken(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", `GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)
	patterns := GetPatterns(nil)
	findings, _, err := ScanFiles(context.Background(), dir, patterns, false, 2*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.PatternType == "github_token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("github_token not found among %d findings", len(findings))
	}
}
