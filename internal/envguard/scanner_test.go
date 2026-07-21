package envguard

import (
	"testing"
)

func TestNewSecretScanner(t *testing.T) {
	scanner := NewSecretScanner()
	if scanner == nil {
		t.Fatal("NewSecretScanner returned nil")
	}
	if len(scanner.patterns) != 6 {
		t.Fatalf("expected 6 patterns, got %d", len(scanner.patterns))
	}
}

func TestScan_AWSAccessKey(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/config.go
+++ b/config.go
@@ -1,3 +1,5 @@
 package config
 
+const awsKey = "AKIAIOSFODNN7EXAMPLE"
+const other = "hello"
 var x = 1
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "aws_access_key" {
		t.Errorf("expected secret_type 'aws_access_key', got %q", f.SecretType)
	}
	if f.FilePath != "config.go" {
		t.Errorf("expected file_path 'config.go', got %q", f.FilePath)
	}
	if f.LineNumber != 3 {
		t.Errorf("expected line_number 3, got %d", f.LineNumber)
	}
	if f.SecretValue != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("expected SecretValue 'AKIAIOSFODNN7EXAMPLE', got %q", f.SecretValue)
	}
}

func TestScan_AWSSecretKey(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/env.sh
+++ b/env.sh
@@ -1,2 +1,3 @@
 export AWS_REGION=us-east-1
+aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 export OTHER=val
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "aws_secret_key" {
		t.Errorf("expected secret_type 'aws_secret_key', got %q", f.SecretType)
	}
	if f.FilePath != "env.sh" {
		t.Errorf("expected file_path 'env.sh', got %q", f.FilePath)
	}
	if f.LineNumber != 2 {
		t.Errorf("expected line_number 2, got %d", f.LineNumber)
	}
}

func TestScan_GenericAPIKey(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/service.go
+++ b/service.go
@@ -5,3 +5,4 @@
 func init() {
+    apiKey := "sk-abcdefghijklmnopqrstuvwx"
 }
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "generic_api_key" {
		t.Errorf("expected secret_type 'generic_api_key', got %q", f.SecretType)
	}
	if f.LineNumber != 6 {
		t.Errorf("expected line_number 6, got %d", f.LineNumber)
	}
}

func TestScan_PrivateKey(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/key.pem
+++ b/key.pem
@@ -0,0 +1,3 @@
+-----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA...
+-----END RSA PRIVATE KEY-----
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "private_key" {
		t.Errorf("expected secret_type 'private_key', got %q", f.SecretType)
	}
	if f.FilePath != "key.pem" {
		t.Errorf("expected file_path 'key.pem', got %q", f.FilePath)
	}
	if f.LineNumber != 1 {
		t.Errorf("expected line_number 1, got %d", f.LineNumber)
	}
}

func TestScan_DatabaseDSN(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/db.go
+++ b/db.go
@@ -10,3 +10,4 @@
 func connect() {
+    dsn := postgres://admin:secretpass@db.example.com:5432/mydb
 }
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "database_dsn" {
		t.Errorf("expected secret_type 'database_dsn', got %q", f.SecretType)
	}
	if f.LineNumber != 11 {
		t.Errorf("expected line_number 11, got %d", f.LineNumber)
	}
	if f.SecretValue != "postgres://admin:secretpass@db.example.com:5432/mydb" {
		t.Errorf("unexpected SecretValue: %q", f.SecretValue)
	}
}

func TestScan_JWTToken(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/auth.go
+++ b/auth.go
@@ -1,2 +1,3 @@
 package auth
+var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
 func verify() {}
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.SecretType != "jwt_token" {
		t.Errorf("expected secret_type 'jwt_token', got %q", f.SecretType)
	}
	if f.LineNumber != 2 {
		t.Errorf("expected line_number 2, got %d", f.LineNumber)
	}
}

func TestScan_LineNumberTracking(t *testing.T) {
	scanner := NewSecretScanner()
	// Hunk starts at line 10. Added lines are at positions 10, 13 (with context lines between).
	diff := `--- a/app.go
+++ b/app.go
@@ -8,5 +10,7 @@
+AKIAIOSFODNN7EXAMPLE1
 context line 1
 context line 2
+AKIAIOSFODNN7EXAMPLE2
 context line 3
`
	findings := scanner.Scan(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].LineNumber != 10 {
		t.Errorf("expected first finding at line 10, got %d", findings[0].LineNumber)
	}
	if findings[1].LineNumber != 13 {
		t.Errorf("expected second finding at line 13, got %d", findings[1].LineNumber)
	}
}

func TestScan_FilePathExtraction(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/pkg/nested/file.go
+++ b/pkg/nested/file.go
@@ -1,2 +1,3 @@
 package nested
+const key = "AKIAIOSFODNN7EXAMPLE"
 var x = 1
`
	findings := scanner.Scan(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FilePath != "pkg/nested/file.go" {
		t.Errorf("expected file_path 'pkg/nested/file.go', got %q", findings[0].FilePath)
	}
}

func TestScan_ContextLinesNotScanned(t *testing.T) {
	scanner := NewSecretScanner()
	// Only the "+" line should be scanned; context and "-" lines should be ignored.
	diff := `--- a/safe.go
+++ b/safe.go
@@ -1,4 +1,4 @@
 package safe
-old_aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 AKIAIOSFODNN7EXAMPLE
+var clean = "no secrets here"
`
	findings := scanner.Scan(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (secrets are in context/deleted lines), got %d", len(findings))
	}
}

func TestScan_NoFalsePositivesOnContextLines(t *testing.T) {
	scanner := NewSecretScanner()
	// The secret is in a context line (no "+" prefix), not an added line.
	diff := `--- a/example.go
+++ b/example.go
@@ -1,3 +1,4 @@
 package example
 const existingKey = "AKIAIOSFODNN7EXAMPLE"
+var newVar = "not-a-secret"
 func main() {}
`
	findings := scanner.Scan(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings (secret is in context line), got %d", len(findings))
	}
}

func TestScan_MultipleSecretsInOneDiff(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/multi.go
+++ b/multi.go
@@ -1,2 +1,5 @@
 package multi
+const key = "AKIAIOSFODNN7EXAMPLE"
+const dsn = "mysql://root:password@localhost/db"
+const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
 func main() {}
`
	findings := scanner.Scan(diff)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	types := map[string]bool{}
	for _, f := range findings {
		types[f.SecretType] = true
	}
	if !types["aws_access_key"] {
		t.Error("expected aws_access_key finding")
	}
	if !types["database_dsn"] {
		t.Error("expected database_dsn finding")
	}
	if !types["jwt_token"] {
		t.Error("expected jwt_token finding")
	}
}

func TestScan_EmptyDiff(t *testing.T) {
	scanner := NewSecretScanner()
	findings := scanner.Scan("")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty diff, got %d", len(findings))
	}
}

func TestScan_MultipleFilesInDiff(t *testing.T) {
	scanner := NewSecretScanner()
	diff := `--- a/file1.go
+++ b/file1.go
@@ -1,2 +1,3 @@
 package file1
+const k1 = "AKIAIOSFODNN7EXAMPLE"
 var x = 1
--- a/file2.go
+++ b/file2.go
@@ -1,2 +1,3 @@
 package file2
+const k2 = "-----BEGIN RSA PRIVATE KEY-----"
 var y = 2
`
	findings := scanner.Scan(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].FilePath != "file1.go" {
		t.Errorf("expected first finding in 'file1.go', got %q", findings[0].FilePath)
	}
	if findings[1].FilePath != "file2.go" {
		t.Errorf("expected second finding in 'file2.go', got %q", findings[1].FilePath)
	}
}

func TestScan_PrivateKeyVariants(t *testing.T) {
	scanner := NewSecretScanner()

	tests := []struct {
		name string
		line string
	}{
		{"RSA", "-----BEGIN RSA PRIVATE KEY-----"},
		{"EC", "-----BEGIN EC PRIVATE KEY-----"},
		{"DSA", "-----BEGIN DSA PRIVATE KEY-----"},
		{"OPENSSH", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"Generic", "-----BEGIN PRIVATE KEY-----"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diff := "--- a/key.pem\n+++ b/key.pem\n@@ -0,0 +1,1 @@\n+" + tc.line + "\n"
			findings := scanner.Scan(diff)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding for %s, got %d", tc.name, len(findings))
			}
			if findings[0].SecretType != "private_key" {
				t.Errorf("expected 'private_key', got %q", findings[0].SecretType)
			}
		})
	}
}

func TestScan_DatabaseDSNVariants(t *testing.T) {
	scanner := NewSecretScanner()

	tests := []struct {
		name string
		dsn  string
	}{
		{"Postgres", "postgres://user:pass@host:5432/db"},
		{"MySQL", "mysql://user:pass@host:3306/db"},
		{"MongoDB", "mongodb://user:pass@host:27017/db"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			diff := "--- a/db.go\n+++ b/db.go\n@@ -1,1 +1,2 @@\n pkg\n+" + tc.dsn + "\n"
			findings := scanner.Scan(diff)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding for %s DSN, got %d", tc.name, len(findings))
			}
			if findings[0].SecretType != "database_dsn" {
				t.Errorf("expected 'database_dsn', got %q", findings[0].SecretType)
			}
		})
	}
}
