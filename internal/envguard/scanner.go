// Package envguard implements the Env-Guard secrets detection and migration module.
package envguard

import (
	"regexp"
	"strconv"
	"strings"
)

// SecretFinding represents a detected secret in a diff.
type SecretFinding struct {
	LineNumber   int    `json:"line_number"`
	FilePath     string `json:"file_path"`
	SecretType   string `json:"secret_type"`
	SecretValue  string `json:"secret_value,omitempty"`
	Replacement  string `json:"replacement,omitempty"`
	MigratedARN  string `json:"migrated_arn,omitempty"`
	MigrationErr string `json:"migration_error,omitempty"`
}

// secretPattern pairs a pattern name with its compiled regex.
type secretPattern struct {
	name  string
	regex *regexp.Regexp
}

// SecretScanner applies compiled regex patterns against diff lines to detect secrets.
type SecretScanner struct {
	patterns []secretPattern
}

// NewSecretScanner creates a SecretScanner with the built-in secret patterns.
func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		patterns: []secretPattern{
			{
				name:  "aws_access_key",
				regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			},
			{
				name:  "aws_secret_key",
				regex: regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			},
			{
				name:  "generic_api_key",
				regex: regexp.MustCompile(`(?i)(sk-|pk-|key-)[a-zA-Z0-9]{20,}`),
			},
			{
				name:  "private_key",
				regex: regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			},
			{
				name:  "database_dsn",
				regex: regexp.MustCompile(`(?i)(postgres|mysql|mongodb)://[^\s"':]+:[^\s"'@]+@[^\s"']+`),
			},
			{
				name:  "jwt_token",
				regex: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
			},
		},
	}
}

// hunkLineRegex extracts the new file start line from a unified diff hunk header.
// e.g. "@@ -1,3 +1,5 @@" -> captures "1" from the +1,5 segment.
var hunkLineRegex = regexp.MustCompile(`^@@\s+\-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@`)

// Scan parses a unified diff and returns all secret findings.
// It tracks file paths from "+++ b/" lines and line numbers from hunk headers,
// scanning only added lines (those starting with "+", excluding "+++").
func (s *SecretScanner) Scan(diff string) []SecretFinding {
	var findings []SecretFinding

	lines := strings.Split(diff, "\n")
	var currentFile string
	var currentLine int

	for _, line := range lines {
		// Detect file path from "+++ b/..." line.
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}

		// Detect hunk header for line number tracking.
		if strings.HasPrefix(line, "@@") {
			matches := hunkLineRegex.FindStringSubmatch(line)
			if len(matches) >= 2 {
				n, err := strconv.Atoi(matches[1])
				if err == nil {
					currentLine = n
				}
			}
			continue
		}

		// Skip "---" lines (old file indicator).
		if strings.HasPrefix(line, "---") {
			continue
		}

		// Only scan added lines (starting with "+").
		if strings.HasPrefix(line, "+") {
			content := line[1:] // strip the leading "+"
			for _, p := range s.patterns {
				match := p.regex.FindString(content)
				if match != "" {
					findings = append(findings, SecretFinding{
						LineNumber:  currentLine,
						FilePath:    currentFile,
						SecretType:  p.name,
						SecretValue: match,
					})
				}
			}
			currentLine++
			continue
		}

		// Context lines (no prefix or starting with " ") also advance the line counter.
		if !strings.HasPrefix(line, "-") {
			currentLine++
		}
		// Lines starting with "-" are deletions from the old file; don't advance new line counter.
	}

	return findings
}
