package cleanarch

import (
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule defines an architecture constraint between packages.
type Rule struct {
	From  string `yaml:"from" json:"from"`
	To    string `yaml:"to" json:"to"`
	Allow bool   `yaml:"allow" json:"allow"`
	Desc  string `yaml:"description" json:"description,omitempty"`
}

// ArchViolation represents a detected architecture rule violation.
type ArchViolation struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	FromPkg     string `json:"from_pkg"`
	Import      string `json:"import"`
	RuleName    string `json:"rule"`
	Description string `json:"description"`
}

// RulesConfig is the top-level YAML structure for architecture rules.
type RulesConfig struct {
	Rules []Rule `yaml:"rules"`
}

// LoadRules reads a YAML file containing architecture rules.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config RulesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return config.Rules, nil
}

// DefaultRules returns the standard layered architecture rules.
func DefaultRules() []Rule {
	return []Rule{
		{
			From:  "**/domain/**",
			To:    "**/infrastructure/**",
			Allow: false,
			Desc:  "Domain layer must not import infrastructure",
		},
		{
			From:  "**/domain/**",
			To:    "**/presentation/**",
			Allow: false,
			Desc:  "Domain layer must not import presentation",
		},
		{
			From:  "**/infrastructure/**",
			To:    "**/presentation/**",
			Allow: false,
			Desc:  "Infrastructure layer must not import presentation",
		},
	}
}

// Evaluate checks all import edges against the rules and returns violations.
// A violation occurs when an import matches a rule with allow=false.
// Allow rules can whitelist specific imports, overriding deny rules.
func Evaluate(edges []ImportEdge, rules []Rule) []ArchViolation {
	var violations []ArchViolation

	for _, edge := range edges {
		for _, rule := range rules {
			fromMatches := matchGlob(rule.From, edge.FromPkg)
			toMatches := matchGlob(rule.To, edge.ImportPath)

			if fromMatches && toMatches {
				if rule.Allow {
					// Allow rule matches — skip this edge entirely (no violation).
					break
				}
				violations = append(violations, ArchViolation{
					FilePath:    edge.FromFile,
					LineNumber:  edge.LineNumber,
					FromPkg:     edge.FromPkg,
					Import:      edge.ImportPath,
					RuleName:    rule.From + " -> " + rule.To,
					Description: rule.Desc,
				})
				// Once a deny rule matches, record violation and stop checking further rules for this edge.
				break
			}
		}
	}

	return violations
}

// matchGlob performs glob-style matching supporting ** for multi-segment paths.
// ** matches zero or more path segments (separated by /).
// * matches any sequence of non-separator characters within a single segment.
// ? matches any single non-separator character.
func matchGlob(pattern, str string) bool {
	// Normalize separators
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	str = strings.ReplaceAll(str, "\\", "/")

	return doMatchGlob(pattern, str)
}

// doMatchGlob implements recursive glob matching with ** support.
func doMatchGlob(pattern, str string) bool {
	// Split pattern and string into segments
	patternParts := splitPath(pattern)
	strParts := splitPath(str)

	return matchParts(patternParts, strParts)
}

// matchParts recursively matches pattern segments against string segments.
func matchParts(patternParts, strParts []string) bool {
	pi, si := 0, 0

	for pi < len(patternParts) {
		if patternParts[pi] == "**" {
			// ** can match zero or more segments
			pi++
			if pi >= len(patternParts) {
				// ** at the end matches everything remaining
				return true
			}
			// Try matching the rest of pattern against every possible tail of str
			for si <= len(strParts) {
				if matchParts(patternParts[pi:], strParts[si:]) {
					return true
				}
				si++
			}
			return false
		}

		if si >= len(strParts) {
			return false
		}

		// Match single segment using path.Match (supports * and ?)
		matched, _ := path.Match(patternParts[pi], strParts[si])
		if !matched {
			return false
		}

		pi++
		si++
	}

	return si >= len(strParts)
}

// splitPath splits a path into non-empty segments.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
