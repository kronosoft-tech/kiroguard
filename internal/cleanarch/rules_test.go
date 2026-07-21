package cleanarch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()

	if len(rules) != 3 {
		t.Fatalf("expected 3 default rules, got %d", len(rules))
	}

	// Verify domain cannot import infrastructure
	r := rules[0]
	if r.From != "**/domain/**" || r.To != "**/infrastructure/**" || r.Allow != false {
		t.Errorf("rule[0] unexpected: %+v", r)
	}
	if r.Desc != "Domain layer must not import infrastructure" {
		t.Errorf("rule[0] description: got %q", r.Desc)
	}

	// Verify domain cannot import presentation
	r = rules[1]
	if r.From != "**/domain/**" || r.To != "**/presentation/**" || r.Allow != false {
		t.Errorf("rule[1] unexpected: %+v", r)
	}

	// Verify infrastructure cannot import presentation
	r = rules[2]
	if r.From != "**/infrastructure/**" || r.To != "**/presentation/**" || r.Allow != false {
		t.Errorf("rule[2] unexpected: %+v", r)
	}
}

func TestLoadRules(t *testing.T) {
	yamlContent := `rules:
  - from: "**/domain/**"
    to: "**/infra/**"
    allow: false
    description: "Domain must not import infra"
  - from: "**/api/**"
    to: "**/domain/**"
    allow: true
    description: "API may import domain"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].From != "**/domain/**" || rules[0].To != "**/infra/**" || rules[0].Allow != false {
		t.Errorf("rule[0] unexpected: %+v", rules[0])
	}
	if rules[0].Desc != "Domain must not import infra" {
		t.Errorf("rule[0] desc: got %q", rules[0].Desc)
	}

	if rules[1].From != "**/api/**" || rules[1].To != "**/domain/**" || rules[1].Allow != true {
		t.Errorf("rule[1] unexpected: %+v", rules[1])
	}
}

func TestLoadRules_FileNotFound(t *testing.T) {
	_, err := LoadRules("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadRules_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		str     string
		want    bool
	}{
		{"exact match", "domain", "domain", true},
		{"no match", "domain", "infrastructure", false},
		{"double star prefix", "**/domain/**", "myapp/domain/entity", true},
		{"double star prefix deep", "**/domain/**", "a/b/c/domain/entity/model", true},
		{"double star no match", "**/domain/**", "myapp/infra/repo", false},
		{"single star segment", "*/domain/*", "myapp/domain/entity", true},
		{"single star no match multi", "*/domain/*", "a/b/domain/entity", false},
		{"double star at end", "domain/**", "domain/entity/model", true},
		{"double star at end root", "domain/**", "domain/entity", true},
		{"double star at start", "**/entity", "domain/entity", true},
		{"double star matches zero segments", "**/domain/**", "domain/entity", true},
		{"question mark", "dom?in", "domain", true},
		{"question mark no match", "dom?in", "domein", true},
		{"complex glob", "**/infrastructure/**", "myproject/internal/infrastructure/db/repo", true},
		{"presentation layer", "**/presentation/**", "app/presentation/handler", true},
		{"empty string", "**", "", true},
		{"empty pattern no match", "", "something", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.str)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.str, got, tt.want)
			}
		})
	}
}

func TestEvaluate_ViolationsDetected(t *testing.T) {
	edges := []ImportEdge{
		{
			FromFile:   "myapp/domain/service.go",
			LineNumber: 5,
			FromPkg:    "myapp/domain/service",
			ImportPath: "myapp/infrastructure/database",
		},
		{
			FromFile:   "myapp/domain/model.go",
			LineNumber: 3,
			FromPkg:    "myapp/domain/model",
			ImportPath: "myapp/presentation/api",
		},
	}

	rules := DefaultRules()
	violations := Evaluate(edges, rules)

	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}

	v := violations[0]
	if v.FilePath != "myapp/domain/service.go" {
		t.Errorf("violation[0] file path: got %q", v.FilePath)
	}
	if v.LineNumber != 5 {
		t.Errorf("violation[0] line: got %d", v.LineNumber)
	}
	if v.FromPkg != "myapp/domain/service" {
		t.Errorf("violation[0] from_pkg: got %q", v.FromPkg)
	}
	if v.Import != "myapp/infrastructure/database" {
		t.Errorf("violation[0] import: got %q", v.Import)
	}
	if v.Description != "Domain layer must not import infrastructure" {
		t.Errorf("violation[0] description: got %q", v.Description)
	}
}

func TestEvaluate_NoViolationsForCleanArchitecture(t *testing.T) {
	// Clean architecture: presentation imports domain, infrastructure imports domain
	edges := []ImportEdge{
		{
			FromFile:   "app/presentation/handler.go",
			LineNumber: 3,
			FromPkg:    "app/presentation/handler",
			ImportPath: "app/domain/service",
		},
		{
			FromFile:   "app/infrastructure/repo.go",
			LineNumber: 4,
			FromPkg:    "app/infrastructure/repo",
			ImportPath: "app/domain/model",
		},
	}

	rules := DefaultRules()
	violations := Evaluate(edges, rules)

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for clean architecture, got %d: %+v", len(violations), violations)
	}
}

func TestEvaluate_AllowRuleOverridesDeny(t *testing.T) {
	edges := []ImportEdge{
		{
			FromFile:   "myapp/domain/service.go",
			LineNumber: 5,
			FromPkg:    "myapp/domain/service",
			ImportPath: "myapp/infrastructure/logger",
		},
	}

	// Allow rule comes BEFORE the deny rule, whitelisting logger specifically
	rules := []Rule{
		{
			From:  "**/domain/**",
			To:    "**/infrastructure/logger",
			Allow: true,
			Desc:  "Domain may use shared logger",
		},
		{
			From:  "**/domain/**",
			To:    "**/infrastructure/**",
			Allow: false,
			Desc:  "Domain must not import infrastructure",
		},
	}

	violations := Evaluate(edges, rules)

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations (allow rule should override), got %d: %+v", len(violations), violations)
	}
}

func TestEvaluate_DenyRuleWithoutAllow(t *testing.T) {
	edges := []ImportEdge{
		{
			FromFile:   "myapp/domain/service.go",
			LineNumber: 10,
			FromPkg:    "myapp/domain/service",
			ImportPath: "myapp/infrastructure/database",
		},
	}

	// Only a deny rule, no allow override
	rules := []Rule{
		{
			From:  "**/domain/**",
			To:    "**/infrastructure/**",
			Allow: false,
			Desc:  "Domain must not import infrastructure",
		},
	}

	violations := Evaluate(edges, rules)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

func TestEvaluate_EmptyEdges(t *testing.T) {
	rules := DefaultRules()
	violations := Evaluate(nil, rules)

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations for empty edges, got %d", len(violations))
	}
}

func TestEvaluate_EmptyRules(t *testing.T) {
	edges := []ImportEdge{
		{
			FromFile:   "a/domain/x.go",
			LineNumber: 1,
			FromPkg:    "a/domain/x",
			ImportPath: "a/infrastructure/y",
		},
	}

	violations := Evaluate(edges, nil)

	if len(violations) != 0 {
		t.Fatalf("expected 0 violations with no rules, got %d", len(violations))
	}
}

func TestEvaluate_InfrastructureImportingPresentation(t *testing.T) {
	edges := []ImportEdge{
		{
			FromFile:   "app/infrastructure/notifier.go",
			LineNumber: 7,
			FromPkg:    "app/infrastructure/notifier",
			ImportPath: "app/presentation/handler",
		},
	}

	rules := DefaultRules()
	violations := Evaluate(edges, rules)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Description != "Infrastructure layer must not import presentation" {
		t.Errorf("wrong description: %q", violations[0].Description)
	}
}
