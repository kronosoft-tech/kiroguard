package piiguard

import (
	"testing"
)

func TestShannonEntropy_Low(t *testing.T) {
	e := ShannonEntropy("hello world")
	// Plain English should have low entropy
	if e >= 4.5 {
		t.Errorf("expected low entropy, got %f", e)
	}
}

func TestShannonEntropy_High(t *testing.T) {
	s := "aB3dE5fG7hI9kL1mN2oP4qR6sT8uV0wX2yZ4"
	e := ShannonEntropy(s)
	if e < 4.5 {
		t.Errorf("expected high entropy (>=4.5), got %f", e)
	}
}

func TestShannonEntropy_Empty(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Errorf("expected 0, got %f", e)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	if e := ShannonEntropy("aaaa"); e != 0 {
		t.Errorf("expected 0 for single char, got %f", e)
	}

	e := ShannonEntropy("ab")
	if e <= 0 {
		t.Error("expected positive entropy for two chars")
	}
}

func TestIsHighEntropy_AboveThreshold(t *testing.T) {
	s := "aB3dE5fG7hI9kL1mN2oP4qR6sT8uV0wX2yZ4"
	if !IsHighEntropy(s, 4.5) {
		t.Error("expected high entropy")
	}
}

func TestIsHighEntropy_BelowThreshold(t *testing.T) {
	if IsHighEntropy("hello world", 4.5) {
		t.Error("expected not high entropy")
	}
}

func TestExtractStringLiterals_GoSource(t *testing.T) {
	content := []byte("x := \"hello world\"; y := 'a'; z := `raw`")
	literals := extractStringLiterals(content)
	if len(literals) == 0 {
		t.Fatal("expected string literals")
	}
	found := false
	for _, l := range literals {
		if l == "hello world" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'hello world' in literals, got %v", literals)
	}
}

func TestExtractStringLiterals_None(t *testing.T) {
	literals := extractStringLiterals([]byte(`var x = 42`))
	if len(literals) != 0 {
		t.Errorf("expected no literals, got %v", literals)
	}
}

func TestExtractStringLiterals_EmptyString(t *testing.T) {
	literals := extractStringLiterals([]byte(`s := ""`))
	if len(literals) != 1 || literals[0] != "" {
		t.Errorf("expected one empty literal, got %v", literals)
	}
}

func TestExtractStringLiterals_Multiple(t *testing.T) {
	content := []byte(`a := "first"; b := "second"`)
	literals := extractStringLiterals(content)
	if len(literals) != 2 {
		t.Errorf("expected 2 literals, got %v", literals)
	}
}

func TestExtractStringLiterals_Unclosed(t *testing.T) {
	content := []byte(`s := "unclosed`)
	literals := extractStringLiterals(content)
	if len(literals) != 1 {
		t.Errorf("expected 1 literal (unclosed), got %v", literals)
	}
}
