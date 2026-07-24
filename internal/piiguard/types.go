package piiguard

import (
	"regexp"
	"sync/atomic"
)

type PIIFinding struct {
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	PatternType string `json:"pattern_type"`
	Severity    string `json:"severity"`
	MatchSample string `json:"match_sample"`
	Context     string `json:"context"`
}

type Summary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByPatternType map[string]int `json:"by_pattern_type"`
	ScanTimeMs    int64          `json:"scan_time_ms"`
	FilesScanned  int            `json:"files_scanned"`
	FilesSkipped  int            `json:"files_skipped"`
}

type VerificationResult struct {
	RequestID   string           `json:"request_id"`
	Verdicts    []FindingVerdict `json:"verdicts"`
	GeneratedAt string           `json:"generated_at"`
}

type FindingVerdict struct {
	FilePath       string `json:"file_path"`
	LineNumber     int    `json:"line_number"`
	PatternType    string `json:"pattern_type"`
	IsTruePositive bool   `json:"is_true_positive"`
	LLMReason      string `json:"llm_reason,omitempty"`
}

type PIIPattern struct {
	Name        string
	Severity    string
	Category    string
	Regex       *regexp.Regexp
	Description string
}

type Metrics struct {
	ScansTotal          atomic.Int64
	FindingsTotal       atomic.Int64
	CriticalFindings    atomic.Int64
	VerificationsOK     atomic.Int64
	VerificationsFailed atomic.Int64
}

type MetricsSnapshot struct {
	ScansTotal          int64 `json:"scans_total"`
	FindingsTotal       int64 `json:"findings_total"`
	CriticalFindings    int64 `json:"critical_findings"`
	VerificationsOK     int64 `json:"verifications_ok"`
	VerificationsFailed int64 `json:"verifications_failed"`
}

type PIIParams struct {
	DirectoryPath     string   `json:"directory_path"`
	SeverityThreshold string   `json:"severity_threshold"`
	Patterns          []string `json:"patterns"`
	EntropyCheck      *bool    `json:"entropy_check"`
}

type PIIResponse struct {
	Findings   []PIIFinding `json:"findings"`
	Summary    Summary      `json:"summary"`
	ScanTimeMs int64        `json:"scan_time_ms"`
	RequestID  string       `json:"request_id,omitempty"`
}
