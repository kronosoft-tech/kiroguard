package iamguard

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IACWildcard represents a wildcard IAM statement found in an IaC file.
type IACWildcard struct {
	FilePath   string `json:"file_path"`
	LineNumber int    `json:"line_number"`
	FileType   string `json:"file_type"`
	Statement  string `json:"statement"`
	Risk       string `json:"risk"` // always "critical"
}

// defaultMaxIACFileSize is the default maximum IaC file size in bytes (5MB).
const defaultMaxIACFileSize = 5 * 1024 * 1024

var iacExtensions = map[string]string{
	".tf":      "terraform",
	".tf.json": "terraform",
	".yaml":    "yaml",
	".yml":     "yaml",
	".json":    "json",
	".ts":      "typescript",
}

var (
	actionStarRE   = regexp.MustCompile(`"?Action"?\s*[:=]\s*"?(\*|\["\*"\])\s*"?`)
	resourceStarRE = regexp.MustCompile(`"?Resource"?\s*[:=]\s*"?(\*|\["\*"\])\s*"?`)
)

// fileTypeFromExt returns a human-readable IaC file type for a file extension.
func fileTypeFromExt(ext string) string {
	if ft, ok := iacExtensions[ext]; ok {
		return ft
	}
	return "unknown"
}

// isIACFile checks whether a file should be scanned for wildcards.
func isIACFile(name string) bool {
	for ext := range iacExtensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// ScanIACForWildcards walks dir recursively, reads IaC files, and detects
// "Action": "*" and "Resource": "*" wildcard IAM statements. Files larger than
// maxSize bytes are skipped with a warning. Pass 0 to use the default (5MB).
func ScanIACForWildcards(dir string, maxSize int64) ([]IACWildcard, error) {
	var wildcards []IACWildcard

	if maxSize <= 0 {
		maxSize = defaultMaxIACFileSize
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "node_modules" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		if !isIACFile(d.Name()) {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}
		if info.Size() > maxSize {
			slog.Warn("iac file exceeds size limit, skipping",
				"file", path,
				"size_bytes", info.Size(),
				"max_bytes", maxSize)
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		ext := filepath.Ext(d.Name())
		ft := fileTypeFromExt(ext)
		lines := strings.Split(string(data), "\n")

		for i, line := range lines {
			match := actionStarRE.FindString(line)
			if match != "" {
				wildcards = append(wildcards, IACWildcard{
					FilePath:   path,
					LineNumber: i + 1,
					FileType:   ft,
					Statement:  match,
					Risk:       "critical",
				})
			}
			match = resourceStarRE.FindString(line)
			if match != "" {
				wildcards = append(wildcards, IACWildcard{
					FilePath:   path,
					LineNumber: i + 1,
					FileType:   ft,
					Statement:  match,
					Risk:       "critical",
				})
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan iac wildcards: %w", err)
	}

	return wildcards, nil
}
