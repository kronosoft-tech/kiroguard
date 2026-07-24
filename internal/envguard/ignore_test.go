package envguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewIgnoreParser_CommentsIgnored(t *testing.T) {
	content := "# this is a comment\n# another comment\n"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parser.patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(parser.patterns))
	}
}

func TestNewIgnoreParser_EmptyLinesIgnored(t *testing.T) {
	content := "\n\n   \n\t\n"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parser.patterns) != 0 {
		t.Errorf("expected 0 patterns, got %d", len(parser.patterns))
	}
}

func TestNewIgnoreParser_GlobPatterns(t *testing.T) {
	content := "*.env\nconfig/?.yaml\nkeys/[abc].pem"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parser.patterns) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(parser.patterns))
	}
	for _, p := range parser.patterns {
		if !p.isGlob {
			t.Errorf("expected pattern %q to be glob", p.raw)
		}
	}
}

func TestNewIgnoreParser_RegexPatterns(t *testing.T) {
	content := "AKIA[0-9A-Z]{16}\nsk-[a-zA-Z0-9]+"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parser.patterns) != 2 {
		t.Fatalf("expected 2 patterns, got %d", len(parser.patterns))
	}
	// These contain '[' so they are treated as glob patterns
	// Actually, '[' triggers glob detection, let's verify
	for _, p := range parser.patterns {
		if !p.isGlob {
			t.Errorf("expected pattern %q to be glob (contains '[')", p.raw)
		}
	}
}

func TestNewIgnoreParser_PureRegexPattern(t *testing.T) {
	// A pattern without *, ?, or [ is treated as regex
	content := "secret_value_123"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(parser.patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(parser.patterns))
	}
	if parser.patterns[0].isGlob {
		t.Error("expected pattern to be regex, not glob")
	}
}

func TestNewIgnoreParser_InvalidGlobReturnsError(t *testing.T) {
	// An unclosed bracket glob is recognized as glob but produces invalid regex
	content := "[invalid"
	_, err := NewIgnoreParser(content)
	if err == nil {
		t.Fatal("expected error for invalid glob, got nil")
	}
}

func TestNewIgnoreParser_InvalidRegexReturnsError(t *testing.T) {
	// An unclosed group is invalid regex but doesn't contain *, ?, or [
	content := "(unclosed"
	_, err := NewIgnoreParser(content)
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestMatch_GlobStar(t *testing.T) {
	parser, err := NewIgnoreParser("*.env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"production.env", true},
		{".env", true},
		{"my.env", true},
		{"envfile", false},
		{"config.yaml", false},
	}

	for _, tt := range tests {
		got := parser.Match(tt.input)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatch_GlobQuestion(t *testing.T) {
	parser, err := NewIgnoreParser("config?.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"config1.yaml", true},
		{"configA.yaml", true},
		{"config.yaml", false},   // ? requires exactly one char
		{"config12.yaml", false}, // ? is only one char
	}

	for _, tt := range tests {
		got := parser.Match(tt.input)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatch_GlobBracket(t *testing.T) {
	parser, err := NewIgnoreParser("key[abc].pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"keya.pem", true},
		{"keyb.pem", true},
		{"keyc.pem", true},
		{"keyd.pem", false},
		{"key1.pem", false},
	}

	for _, tt := range tests {
		got := parser.Match(tt.input)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatch_RegexPattern(t *testing.T) {
	parser, err := NewIgnoreParser("secret_value_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"secret_value_123", true},
		{"has secret_value_123 inside", true}, // regex substring match
		{"other_value", false},
	}

	for _, tt := range tests {
		got := parser.Match(tt.input)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatch_MultiplePatterns(t *testing.T) {
	content := "# Ignore env files and test keys\n*.env\ntest_key_\\d+"
	parser, err := NewIgnoreParser(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		input string
		want  bool
	}{
		{"production.env", true},
		{"test_key_42", true},
		{"real_key", false},
	}

	for _, tt := range tests {
		got := parser.Match(tt.input)
		if got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestMatch_EmptyParser(t *testing.T) {
	parser, err := NewIgnoreParser("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parser.Match("anything") {
		t.Error("empty parser should not match anything")
	}
}

func TestFilter_ExcludesMatchedFindings(t *testing.T) {
	parser, err := NewIgnoreParser("*.test\nfake_secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	findings := []SecretFinding{
		{LineNumber: 1, FilePath: "config.test", SecretType: "api_key", SecretValue: "real_key_123"},
		{LineNumber: 2, FilePath: "main.go", SecretType: "aws_key", SecretValue: "fake_secret_value"},
		{LineNumber: 3, FilePath: "app.go", SecretType: "jwt", SecretValue: "actual_token"},
	}

	result := parser.Filter(findings)

	// Finding 1: FilePath "config.test" matches "*.test" → excluded
	// Finding 2: Value "fake_secret_value" matches "fake_secret" (regex substring) → excluded
	// Finding 3: neither matches → kept
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(result))
	}
	if result[0].LineNumber != 3 {
		t.Errorf("expected finding at line 3, got line %d", result[0].LineNumber)
	}
}

func TestFilter_PreservesUnmatchedFindings(t *testing.T) {
	parser, err := NewIgnoreParser("nonexistent_pattern")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	findings := []SecretFinding{
		{LineNumber: 1, FilePath: "main.go", SecretType: "aws_key", SecretValue: "AKIAIOSFODNN7EXAMPLE"},
		{LineNumber: 5, FilePath: "config.go", SecretType: "db_dsn", SecretValue: "postgres://user:pass@host/db"},
	}

	result := parser.Filter(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2 findings preserved, got %d", len(result))
	}
}

func TestFilter_EmptyFindings(t *testing.T) {
	parser, err := NewIgnoreParser("*.env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := parser.Filter(nil)
	if result != nil {
		t.Errorf("expected nil result for nil input, got %v", result)
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	// Create a temp file for testing
	dir := t.TempDir()
	path := filepath.Join(dir, ".envguardignore")
	content := "# test ignore\n*.env\ntest_secret"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	parser, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !parser.Match("config.env") {
		t.Error("expected config.env to match")
	}
	if !parser.Match("test_secret") {
		t.Error("expected test_secret to match")
	}
}

func TestLoadIgnoreFile_FileNotFound(t *testing.T) {
	_, err := LoadIgnoreFile("/nonexistent/.envguardignore")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
