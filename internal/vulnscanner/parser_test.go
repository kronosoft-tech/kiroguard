package vulnscanner

import (
	"sort"
	"testing"
)

func TestParseManifest_NPM_DependenciesAndDevDependencies(t *testing.T) {
	content := `{
		"name": "my-app",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "~4.17.21"
		},
		"devDependencies": {
			"jest": ">=29.0.0",
			"typescript": "5.3.3"
		}
	}`

	deps, err := ParseManifest(content, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	// Sort for deterministic comparison
	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expected := []Dependency{
		{Name: "express", Version: "4.18.0", Ecosystem: "npm"},
		{Name: "jest", Version: "29.0.0", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "typescript", Version: "5.3.3", Ecosystem: "npm"},
	}

	for i, dep := range deps {
		if dep.Name != expected[i].Name {
			t.Errorf("dep[%d].Name = %q, want %q", i, dep.Name, expected[i].Name)
		}
		if dep.Version != expected[i].Version {
			t.Errorf("dep[%d].Version = %q, want %q", i, dep.Version, expected[i].Version)
		}
		if dep.Ecosystem != expected[i].Ecosystem {
			t.Errorf("dep[%d].Ecosystem = %q, want %q", i, dep.Ecosystem, expected[i].Ecosystem)
		}
	}
}

func TestParseManifest_NPM_VersionPrefixStripping(t *testing.T) {
	content := `{
		"dependencies": {
			"a": "^1.2.3",
			"b": "~2.3.4",
			"c": ">=3.0.0",
			"d": "<=4.0.0",
			"e": ">5.0.0",
			"f": "<6.0.0",
			"g": "=7.0.0",
			"h": "1.0.0"
		}
	}`

	deps, err := ParseManifest(content, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expectedVersions := map[string]string{
		"a": "1.2.3",
		"b": "2.3.4",
		"c": "3.0.0",
		"d": "4.0.0",
		"e": "5.0.0",
		"f": "6.0.0",
		"g": "7.0.0",
		"h": "1.0.0",
	}

	for _, dep := range deps {
		want, ok := expectedVersions[dep.Name]
		if !ok {
			t.Errorf("unexpected dep: %q", dep.Name)
			continue
		}
		if dep.Version != want {
			t.Errorf("dep %q version = %q, want %q", dep.Name, dep.Version, want)
		}
	}
}

func TestParseManifest_NPM_PackageLockFormat(t *testing.T) {
	content := `{
		"name": "my-app",
		"lockfileVersion": 3,
		"packages": {
			"": {
				"name": "my-app",
				"version": "1.0.0"
			},
			"node_modules/express": {
				"version": "4.18.2"
			},
			"node_modules/@types/node": {
				"version": "20.10.0"
			}
		}
	}`

	deps, err := ParseManifest(content, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d: %+v", len(deps), deps)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	if deps[0].Name != "@types/node" || deps[0].Version != "20.10.0" {
		t.Errorf("dep[0] = %+v, want @types/node@20.10.0", deps[0])
	}
	if deps[1].Name != "express" || deps[1].Version != "4.18.2" {
		t.Errorf("dep[1] = %+v, want express@4.18.2", deps[1])
	}
}

func TestParseManifest_NPM_LegacyLockFormat(t *testing.T) {
	content := `{
		"name": "my-app",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
			},
			"lodash": {
				"version": "4.17.21"
			}
		}
	}`

	deps, err := ParseManifest(content, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d: %+v", len(deps), deps)
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	if deps[0].Name != "express" || deps[0].Version != "4.18.2" {
		t.Errorf("dep[0] = %+v, want express@4.18.2", deps[0])
	}
	if deps[1].Name != "lodash" || deps[1].Version != "4.17.21" {
		t.Errorf("dep[1] = %+v, want lodash@4.17.21", deps[1])
	}
}

func TestParseManifest_NPM_InvalidJSON(t *testing.T) {
	content := `{invalid json`

	_, err := ParseManifest(content, "npm")
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseManifest_NPM_EmptyManifest(t *testing.T) {
	content := `{}`

	deps, err := ParseManifest(content, "npm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(deps))
	}
}

func TestParseManifest_Pip_ValidRequirements(t *testing.T) {
	content := `flask==2.3.0
requests>=2.28.0
numpy==1.24.3
pandas>=1.5.0
`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expected := []Dependency{
		{Name: "flask", Version: "2.3.0", Ecosystem: "pypi"},
		{Name: "numpy", Version: "1.24.3", Ecosystem: "pypi"},
		{Name: "pandas", Version: "1.5.0", Ecosystem: "pypi"},
		{Name: "requests", Version: "2.28.0", Ecosystem: "pypi"},
	}

	for i, dep := range deps {
		if dep.Name != expected[i].Name {
			t.Errorf("dep[%d].Name = %q, want %q", i, dep.Name, expected[i].Name)
		}
		if dep.Version != expected[i].Version {
			t.Errorf("dep[%d].Version = %q, want %q", i, dep.Version, expected[i].Version)
		}
		if dep.Ecosystem != expected[i].Ecosystem {
			t.Errorf("dep[%d].Ecosystem = %q, want %q", i, dep.Ecosystem, expected[i].Ecosystem)
		}
	}
}

func TestParseManifest_Pip_CommentsAndEmptyLines(t *testing.T) {
	content := `# This is a comment
flask==2.3.0

# Another comment
requests==2.28.0

`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	if deps[0].Name != "flask" || deps[0].Version != "2.3.0" {
		t.Errorf("dep[0] = %+v, want flask@2.3.0", deps[0])
	}
	if deps[1].Name != "requests" || deps[1].Version != "2.28.0" {
		t.Errorf("dep[1] = %+v, want requests@2.28.0", deps[1])
	}
}

func TestParseManifest_Pip_FlagsIgnored(t *testing.T) {
	content := `-r base.txt
-e git+https://github.com/user/repo.git
--index-url https://pypi.org/simple
flask==2.3.0
`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d: %+v", len(deps), deps)
	}

	if deps[0].Name != "flask" || deps[0].Version != "2.3.0" {
		t.Errorf("dep[0] = %+v, want flask@2.3.0", deps[0])
	}
}

func TestParseManifest_Pip_NoVersionConstraint(t *testing.T) {
	content := `flask
requests
numpy
`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	for _, dep := range deps {
		if dep.Version != "" {
			t.Errorf("dep %q should have empty version, got %q", dep.Name, dep.Version)
		}
		if dep.Ecosystem != "pypi" {
			t.Errorf("dep %q ecosystem = %q, want pypi", dep.Name, dep.Ecosystem)
		}
	}
}

func TestParseManifest_Pip_AllOperators(t *testing.T) {
	content := `a==1.0.0
b>=2.0.0
c<=3.0.0
d!=4.0.0
e~=5.0.0
`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 5 {
		t.Fatalf("expected 5 dependencies, got %d", len(deps))
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	expectedVersions := map[string]string{
		"a": "1.0.0",
		"b": "2.0.0",
		"c": "3.0.0",
		"d": "4.0.0",
		"e": "5.0.0",
	}

	for _, dep := range deps {
		want := expectedVersions[dep.Name]
		if dep.Version != want {
			t.Errorf("dep %q version = %q, want %q", dep.Name, dep.Version, want)
		}
	}
}

func TestParseManifest_Pip_EmptyManifest(t *testing.T) {
	content := ``

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(deps))
	}
}

func TestParseManifest_UnsupportedEcosystem(t *testing.T) {
	_, err := ParseManifest("content", "cargo")
	if err == nil {
		t.Fatal("expected error for unsupported ecosystem, got nil")
	}
}

func TestParseManifest_Pip_InlineComments(t *testing.T) {
	content := `flask==2.3.0 # web framework
requests==2.28.0 # http client
`

	deps, err := ParseManifest(content, "pip")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	sort.Slice(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })

	if deps[0].Name != "flask" || deps[0].Version != "2.3.0" {
		t.Errorf("dep[0] = %+v, want flask@2.3.0", deps[0])
	}
	if deps[1].Name != "requests" || deps[1].Version != "2.28.0" {
		t.Errorf("dep[1] = %+v, want requests@2.28.0", deps[1])
	}
}
