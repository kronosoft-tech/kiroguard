package iamguard

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFileTypeFromExt(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".tf", "terraform"},
		{".tf.json", "terraform"},
		{".yaml", "yaml"},
		{".yml", "yaml"},
		{".json", "json"},
		{".ts", "typescript"},
		{".go", "unknown"},
	}
	for _, tt := range tests {
		got := fileTypeFromExt(tt.ext)
		if got != tt.want {
			t.Errorf("fileTypeFromExt(%q) = %q, want %q", tt.ext, got, tt.want)
		}
	}
}

func TestScanIACForWildcards_JSONActionStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policy.json"), `{
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }
}`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
	if wildcards[0].Risk != "critical" {
		t.Errorf("risk = %q, want %q", wildcards[0].Risk, "critical")
	}
}

func TestScanIACForWildcards_JSONResourceStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policy.json"), `{
  "Statement": {
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }
}`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
}

func TestScanIACForWildcards_TerraformActionStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.tf"), `
resource "aws_iam_policy" "too_broad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
	// Should find both Action=* and Resource=*
	if len(wildcards) < 2 {
		t.Fatalf("expected 2 wildcards (action + resource), got %d", len(wildcards))
	}
}

func TestScanIACForWildcards_TerraformResourceStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.tf"), `
resource "aws_iam_role_policy" "example" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "*"
    }]
  })
}
`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) != 1 {
		t.Fatalf("expected 1 wildcard, got %d", len(wildcards))
	}
}

func TestScanIACForWildcards_YAMLActionStar(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policy.yaml"), `
Statement:
  Effect: Allow
  Action: "*"
  Resource: "arn:aws:s3:::my-bucket/*"
`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) == 0 {
		t.Fatal("expected at least 1 wildcard")
	}
}

func TestScanIACForWildcards_NoWildcards(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "policy.json"), `{
  "Statement": {
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }
}`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) != 0 {
		t.Fatalf("expected 0 wildcards, got %d", len(wildcards))
	}
}

func TestScanIACForWildcards_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) != 0 {
		t.Errorf("expected 0 wildcards, got %d", len(wildcards))
	}
}

func TestScanIACForWildcards_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "node_modules", "somepkg", "policy.json"), `{"Action": "*"}`)
	writeFile(t, filepath.Join(dir, "src", "policy.json"), `{"Action": "s3:GetObject"}`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) != 0 {
		t.Fatalf("expected 0 wildcards (node_modules skipped), got %d", len(wildcards))
	}
}

func TestScanIACForWildcards_FileOver5MB(t *testing.T) {
	dir := t.TempDir()
	largePath := filepath.Join(dir, "large.json")
	f, err := os.Create(largePath)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5*1024*1024+1)
	for i := range data {
		data[i] = ' '
	}
	copy(data, `{"Action": "*"}`)
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	f.Close()

	writeFile(t, filepath.Join(dir, "small.json"), `{"Action": "s3:GetObject"}`)

	wildcards, err := ScanIACForWildcards(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wildcards) != 0 {
		t.Fatalf("expected 0 wildcards (large file skipped), got %d", len(wildcards))
	}
}
