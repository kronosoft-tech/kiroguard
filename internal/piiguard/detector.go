package piiguard

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var supportedExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true,
	".java": true, ".rb": true, ".php": true,
	".yaml": true, ".yml": true, ".json": true, ".tf": true,
	".env": true, ".properties": true, ".ini": true, ".cfg": true, ".conf": true,
	".txt": true, ".md": true,
}

var excludedDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"__pycache__": true, ".venv": true, ".terraform": true,
}

var testSuffixes = []string{
	"_test.go", "_spec.rb", "test_", ".test.js", ".spec.ts", "_test.py",
}

var archiveExtensions = map[string]bool{
	".zip": true, ".tar": true, ".gz": true, ".jar": true,
}

var lockFiles = map[string]bool{
	"package-lock.json": true, "yarn.lock": true,
}

func isTestFile(name string) bool {
	for _, s := range testSuffixes {
		if strings.HasPrefix(name, s) || strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

func isCommentOrEmpty(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	for _, prefix := range []string{"//", "#", "--"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func redactMatch(s string) string {
	if len(s) <= 40 {
		return s
	}
	return s[:20] + "[...]" + s[len(s)-17:]
}

func extractContext(line string, matchStart, matchEnd int) string {
	runes := []rune(line)
	start := matchStart - 50
	if start < 0 {
		start = 0
	}
	end := matchEnd + 50
	if end > len(runes) {
		end = len(runes)
	}
	return string(runes[start:end])
}

func ScanFiles(ctx context.Context, dir string, patterns []PIIPattern, entropyCheck bool, maxFileSize int64) ([]PIIFinding, *Summary, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid directory: %w", err)
	}
	if !stat.IsDir() {
		return nil, nil, fmt.Errorf("path is not a directory: %s", dir)
	}

	var findings []PIIFinding
	filesScanned := 0
	filesSkipped := 0
	seen := make(map[string]bool)

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if excludedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		ext := filepath.Ext(name)

		if archiveExtensions[ext] {
			filesSkipped++
			return nil
		}
		if lockFiles[name] {
			filesSkipped++
			return nil
		}
		if !supportedExtensions[ext] {
			return nil
		}
		if isTestFile(name) {
			filesSkipped++
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}

		if info.Size() == 0 {
			return nil
		}
		if info.Size() > maxFileSize {
			slog.Warn("file exceeds max size, skipping", "path", path, "size_mb", info.Size()/(1024*1024))
			filesSkipped++
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			slog.Warn("failed to read file", "path", path, "error", readErr)
			filesSkipped++
			return nil
		}

		if isBinary(data) {
			filesSkipped++
			return nil
		}

		fileFindings := scanFile(path, data, patterns, entropyCheck, seen)
		findings = append(findings, fileFindings...)
		filesScanned++
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walk dir: %w", err)
	}

	bySeverity := map[string]int{}
	byPatternType := map[string]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
		byPatternType[f.PatternType]++
	}

	summary := &Summary{
		TotalFindings: len(findings),
		BySeverity:    bySeverity,
		ByPatternType: byPatternType,
		FilesScanned:  filesScanned,
		FilesSkipped:  filesSkipped,
	}
	return findings, summary, nil
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	mime := http.DetectContentType(sample)
	return !strings.HasPrefix(mime, "text/") &&
		mime != "application/json" &&
		mime != "application/xml" &&
		mime != "application/yaml" &&
		!strings.HasPrefix(mime, "application/x-httpd-php")
}

func scanFile(path string, data []byte, patterns []PIIPattern, entropyCheck bool, seen map[string]bool) []PIIFinding {
	var findings []PIIFinding
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if isCommentOrEmpty(line) {
			continue
		}

		hasPattern := false
		for _, pat := range patterns {
			if pat.Name == "high_entropy_string" {
				continue
			}
			matches := pat.Regex.FindAllStringIndex(line, -1)
			for _, m := range matches {
				matchText := line[m[0]:m[1]]
				if pat.Name == "credit_card" {
					cleaned := strings.NewReplacer("-", "", " ", "").Replace(matchText)
					if !luhnCheck(cleaned) {
						continue
					}
				}
				hasPattern = true
				dedupKey := fmt.Sprintf("%s:%d:%s", path, lineNum, pat.Name)
				if seen[dedupKey] {
					continue
				}
				seen[dedupKey] = true

				findings = append(findings, PIIFinding{
					FilePath:    path,
					LineNumber:  lineNum,
					PatternType: pat.Name,
					Severity:    pat.Severity,
					MatchSample: redactMatch(matchText),
					Context:     extractContext(line, m[0], m[1]),
				})
			}
		}

		if entropyCheck && !hasPattern {
			literals := extractStringLiterals([]byte(line))
			for _, lit := range literals {
				if len(lit) > 20 && !isCommonLiteral(lit) && IsHighEntropy(lit, 4.5) {
					dedupKey := fmt.Sprintf("%s:%d:%s", path, lineNum, "high_entropy_string")
					if seen[dedupKey] {
						continue
					}
					seen[dedupKey] = true

					litIdx := strings.Index(line, lit)
					if litIdx < 0 {
						litIdx = 0
					}

					findings = append(findings, PIIFinding{
						FilePath:    path,
						LineNumber:  lineNum,
						PatternType: "high_entropy_string",
						Severity:    "medium",
						MatchSample: redactMatch(lit),
						Context:     extractContext(line, litIdx, litIdx+len(lit)),
					})
					break
				}
			}
		}
	}
	return findings
}

func isCommonLiteral(s string) bool {
	common := []string{"http://", "https://", "git@", "ssh://", "ftp://"}
	for _, c := range common {
		if strings.HasPrefix(s, c) {
			return true
		}
	}
	return false
}
