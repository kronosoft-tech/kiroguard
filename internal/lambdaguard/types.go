package lambdaguard

import "sync/atomic"

type LambdaConfig struct {
	FunctionName        string            `json:"function_name"`
	SourceFile          string            `json:"source_file"`
	Runtime             string            `json:"runtime"`
	Timeout             int               `json:"timeout"`
	MemorySize          int               `json:"memory_size"`
	RoleARN             string            `json:"role_arn,omitempty"`
	RoleStatements      []IAMStatement    `json:"role_statements,omitempty"`
	ManagedPolicyARNs   []string          `json:"managed_policy_arns,omitempty"`
	Environment         map[string]string `json:"environment,omitempty"`
	DLQTarget           string            `json:"dlq_target,omitempty"`
	VPCConfig           *VPCConfig        `json:"vpc_config,omitempty"`
	ReservedConcurrency int               `json:"reserved_concurrency"`
	TracingMode         string            `json:"tracing_mode,omitempty"`
	Architectures       []string          `json:"architectures,omitempty"`
	Handler             string            `json:"handler,omitempty"`
	Description         string            `json:"description,omitempty"`
	IaCFormat           string            `json:"iac_format"`
}

type LambdaFinding struct {
	FunctionName string `json:"function_name"`
	SourceFile   string `json:"source_file"`
	CheckID      string `json:"check_id"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Message      string `json:"message"`
	Remediation  string `json:"remediation"`
	CurrentValue string `json:"current_value,omitempty"`
}

type Summary struct {
	TotalFunctions int            `json:"total_functions"`
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByCategory     map[string]int `json:"by_category"`
	ScanTimeMs     int64          `json:"scan_time_ms"`
	FilesScanned   int            `json:"files_scanned"`
}

type IAMStatement struct {
	Effect   string   `json:"effect"`
	Action   []string `json:"action"`
	Resource []string `json:"resource"`
}

type VPCConfig struct {
	SubnetIDs        []string `json:"subnet_ids"`
	SecurityGroupIDs []string `json:"security_group_ids"`
}

type Metrics struct {
	AnalyzesTotal    atomic.Int64
	FunctionsTotal   atomic.Int64
	FindingsTotal    atomic.Int64
	CriticalFindings atomic.Int64
}

type MetricsSnapshot struct {
	AnalyzesTotal    int64 `json:"analyzes_total"`
	FunctionsTotal   int64 `json:"functions_total"`
	FindingsTotal    int64 `json:"findings_total"`
	CriticalFindings int64 `json:"critical_findings"`
}

type Params struct {
	DirectoryPath    string   `json:"directory_path"`
	Checks           []string `json:"checks,omitempty"`
	SeverityThreshold string  `json:"severity_threshold"`
}

type Response struct {
	Functions  []LambdaConfig  `json:"functions"`
	Findings   []LambdaFinding `json:"findings"`
	Summary    Summary         `json:"summary"`
	ScanTimeMs int64           `json:"scan_time_ms"`
}
