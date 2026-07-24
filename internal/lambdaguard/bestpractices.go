package lambdaguard

import (
	"fmt"
	"strings"
)

type Check func(cfg *LambdaConfig) *LambdaFinding

var BestPracticeChecks = []Check{
	checkTimeoutTooLong,
	checkTimeoutDefault,
	checkMemoryTooHigh,
	checkMemoryTooLow,
	checkNoDLQ,
	checkNoVPCForRDS,
	checkNoReservedConcurrency,
	checkRuntimeEOL,
	checkTracingNotActive,
	checkNoDescription,
	checkLatestAlias,
	checkBothArchitectures,
}

var supportedRuntimes = map[string]bool{
	"nodejs20.x":  true,
	"nodejs22.x":  true,
	"python3.11":  true,
	"python3.12":  true,
	"python3.13":  true,
	"java17":      true,
	"java21":      true,
	"dotnet8":     true,
	"dotnet9":     true,
	"go1.x":       true,
	"provided.al2023": true,
	"provided.al2":    true,
	"ruby3.3":     true,
}

var checkNames = []string{
	"LG-1", "LG-2", "LG-3", "LG-4", "LG-5", "LG-6",
	"LG-7", "LG-8", "LG-9", "LG-10", "LG-11", "LG-12",
}

func mkFinding(cfg *LambdaConfig, checkID, severity, category, msg, remediation, value string) *LambdaFinding {
	return &LambdaFinding{
		FunctionName: cfg.FunctionName,
		SourceFile:   cfg.SourceFile,
		CheckID:      checkID,
		Severity:     severity,
		Category:     category,
		Message:      msg,
		Remediation:  remediation,
		CurrentValue: value,
	}
}

func checkTimeoutTooLong(cfg *LambdaConfig) *LambdaFinding {
	if cfg.Timeout > 900 {
		return mkFinding(cfg, "LG-1", "high", "operations",
			fmt.Sprintf("Function %s timeout is %ds, exceeding the 900s API Gateway limit", cfg.FunctionName, cfg.Timeout),
			"Reduce timeout to 900s or less, or use AWS API Gateway HTTP API with timeout override",
			fmt.Sprintf("%d", cfg.Timeout))
	}
	return nil
}

func checkTimeoutDefault(cfg *LambdaConfig) *LambdaFinding {
	if cfg.Timeout == 3 {
		return mkFinding(cfg, "LG-2", "medium", "reliability",
			fmt.Sprintf("Function %s uses default timeout of 3s which may cause timeouts for real workloads", cfg.FunctionName),
			"Set an explicit timeout based on your function's expected execution duration",
			"3")
	}
	return nil
}

func checkMemoryTooHigh(cfg *LambdaConfig) *LambdaFinding {
	if cfg.MemorySize > 3008 {
		return mkFinding(cfg, "LG-3", "low", "cost",
			fmt.Sprintf("Function %s memory is set to %dMB, approaching the 10240MB maximum", cfg.FunctionName, cfg.MemorySize),
			"Consider reducing memory or monitoring actual usage with CloudWatch metrics",
			fmt.Sprintf("%d", cfg.MemorySize))
	}
	return nil
}

func checkMemoryTooLow(cfg *LambdaConfig) *LambdaFinding {
	if cfg.MemorySize < 128 {
		return mkFinding(cfg, "LG-4", "high", "reliability",
			fmt.Sprintf("Function %s memory is %dMB, below the 128MB minimum", cfg.FunctionName, cfg.MemorySize),
			"Set memory to at least 128MB",
			fmt.Sprintf("%d", cfg.MemorySize))
	}
	return nil
}

func checkNoDLQ(cfg *LambdaConfig) *LambdaFinding {
	if cfg.DLQTarget == "" && cfg.Timeout > 60 {
		return mkFinding(cfg, "LG-5", "medium", "reliability",
			fmt.Sprintf("Function %s has no Dead Letter Queue configured despite %ds timeout", cfg.FunctionName, cfg.Timeout),
			"Configure a DLQ (SQS or SNS) to capture failed asynchronous invocations",
			"no DLQ")
	}
	return nil
}

func checkNoVPCForRDS(cfg *LambdaConfig) *LambdaFinding {
	if cfg.VPCConfig == nil {
		for _, stmt := range cfg.RoleStatements {
			for _, action := range stmt.Action {
				if strings.HasPrefix(action, "rds:") || strings.HasPrefix(action, "elasticache:") {
					return mkFinding(cfg, "LG-6", "high", "security",
						fmt.Sprintf("Function %s has RDS/ElastiCache permissions but no VPC configuration", cfg.FunctionName),
						"Configure VPC with the appropriate subnets and security groups to access RDS/ElastiCache",
						"no VPC")
				}
			}
		}
	}
	return nil
}

func checkNoReservedConcurrency(cfg *LambdaConfig) *LambdaFinding {
	if cfg.ReservedConcurrency == -1 || cfg.ReservedConcurrency == 0 {
		return mkFinding(cfg, "LG-7", "low", "cost",
			fmt.Sprintf("Function %s has no reserved concurrency", cfg.FunctionName),
			"Set reserved concurrency to prevent uncontrolled scaling and control costs",
			"not set")
	}
	return nil
}

func checkRuntimeEOL(cfg *LambdaConfig) *LambdaFinding {
	if cfg.Runtime != "" && !supportedRuntimes[cfg.Runtime] {
		return mkFinding(cfg, "LG-8", "medium", "operations",
			fmt.Sprintf("Function %s uses runtime %s which may be deprecated or end-of-life", cfg.FunctionName, cfg.Runtime),
			"Upgrade to a supported runtime version",
			cfg.Runtime)
	}
	return nil
}

func checkTracingNotActive(cfg *LambdaConfig) *LambdaFinding {
	if cfg.TracingMode != "" && cfg.TracingMode != "Active" {
		return mkFinding(cfg, "LG-9", "low", "operations",
			fmt.Sprintf("Function %s has tracing set to %q instead of Active", cfg.FunctionName, cfg.TracingMode),
			"Enable Active tracing for better observability with AWS X-Ray",
			cfg.TracingMode)
	}
	return nil
}

func checkNoDescription(cfg *LambdaConfig) *LambdaFinding {
	if cfg.Description == "" {
		return mkFinding(cfg, "LG-10", "low", "operations",
			fmt.Sprintf("Function %s has no description", cfg.FunctionName),
			"Add a meaningful description to document the function's purpose",
			"")
	}
	return nil
}

func checkLatestAlias(cfg *LambdaConfig) *LambdaFinding {
	if strings.Contains(cfg.Handler, "$LATEST") {
		return mkFinding(cfg, "LG-11", "medium", "reliability",
			fmt.Sprintf("Function %s handler references $LATEST alias", cfg.FunctionName),
			"Use a versioned alias for production deployments to enable rollback",
			cfg.Handler)
	}
	return nil
}

func checkBothArchitectures(cfg *LambdaConfig) *LambdaFinding {
	if len(cfg.Architectures) > 1 {
		return mkFinding(cfg, "LG-12", "low", "cost",
			fmt.Sprintf("Function %s specifies multiple architectures", cfg.FunctionName),
			"Use a single architecture (arm64 is more cost-effective for most workloads)",
			strings.Join(cfg.Architectures, ", "))
	}
	return nil
}

func ApplyBestPractices(cfg *LambdaConfig, checkIDs []string) []LambdaFinding {
	var findings []LambdaFinding

	runAll := len(checkIDs) == 0

	for i, check := range BestPracticeChecks {
		if !runAll {
			found := false
			for _, id := range checkIDs {
				if id == checkNames[i] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if finding := check(cfg); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}
