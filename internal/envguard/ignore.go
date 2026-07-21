package envguard

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ignorePattern represents a single compiled pattern from an .envguardignore file.
type ignorePattern struct {
	raw    string
	isGlob bool
	regex  *regexp.Regexp
}

// IgnoreParser reads .envguardignore content and compiles patterns for matching.
type IgnoreParser struct {
	patterns []ignorePattern
}

// NewIgnoreParser creates an IgnoreParser from the given content string.
// Lines starting with '#' are comments and ignored. Empty lines are skipped.
// Lines containing '*', '?', or '[' are treated as glob patterns.
// All other lines are treated as literal regex patterns.
func NewIgnoreParser(content string) (*IgnoreParser, error) {
	parser := &IgnoreParser{}
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var pat ignorePattern
		pat.raw = line

		if isGlobPattern(line) {
			// Convert glob to regex
			pat.isGlob = true
			regexStr := globToRegex(line)
			compiled, err := regexp.Compile(regexStr)
			if err != nil {
				return nil, fmt.Errorf("failed to compile glob pattern %q: %w", line, err)
			}
			pat.regex = compiled
		} else {
			// Treat as literal regex
			pat.isGlob = false
			compiled, err := regexp.Compile(line)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern %q: %w", line, err)
			}
			pat.regex = compiled
		}

		parser.patterns = append(parser.patterns, pat)
	}

	return parser, nil
}

// LoadIgnoreFile reads an .envguardignore file from the given path and returns a parser.
func LoadIgnoreFile(path string) (*IgnoreParser, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read ignore file %q: %w", path, err)
	}
	return NewIgnoreParser(string(data))
}

// Match returns true if any compiled pattern matches the given line.
func (p *IgnoreParser) Match(line string) bool {
	for _, pat := range p.patterns {
		if pat.regex.MatchString(line) {
			return true
		}
	}
	return false
}

// Filter returns only findings where neither the finding's SecretValue nor its FilePath
// matches any ignore pattern.
func (p *IgnoreParser) Filter(findings []SecretFinding) []SecretFinding {
	var result []SecretFinding
	for _, f := range findings {
		if p.Match(f.SecretValue) || p.Match(f.FilePath) {
			continue
		}
		result = append(result, f)
	}
	return result
}

// isGlobPattern returns true if the line contains glob-specific characters.
func isGlobPattern(line string) bool {
	return strings.ContainsAny(line, "*?[")
}

// globToRegex converts a glob pattern to an equivalent regex string.
// Conversion rules:
//   - '*' → '.*'
//   - '?' → '.'
//   - '[' and ']' pass through as regex character classes
//   - All other special regex characters are escaped
func globToRegex(glob string) string {
	var buf strings.Builder
	buf.WriteString("^")

	inBracket := false
	for i := 0; i < len(glob); i++ {
		ch := glob[i]
		switch {
		case ch == '[':
			inBracket = true
			buf.WriteByte(ch)
		case ch == ']' && inBracket:
			inBracket = false
			buf.WriteByte(ch)
		case ch == '*' && !inBracket:
			buf.WriteString(".*")
		case ch == '?' && !inBracket:
			buf.WriteByte('.')
		case !inBracket && isRegexMeta(ch):
			buf.WriteByte('\\')
			buf.WriteByte(ch)
		default:
			buf.WriteByte(ch)
		}
	}

	buf.WriteString("$")
	return buf.String()
}

// isRegexMeta returns true if the character is a regex metacharacter
// that needs escaping (excluding *, ?, [, ] which are handled by glob logic).
func isRegexMeta(ch byte) bool {
	switch ch {
	case '.', '+', '^', '$', '|', '(', ')', '{', '}', '\\':
		return true
	}
	return false
}
