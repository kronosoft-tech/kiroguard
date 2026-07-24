package lambdaguard

import "fmt"

func AnalyzeIAM(cfg *LambdaConfig) []LambdaFinding {
	var findings []LambdaFinding

	for _, stmt := range cfg.RoleStatements {
		for _, action := range stmt.Action {
			if action == "*" {
				findings = append(findings, LambdaFinding{
					FunctionName: cfg.FunctionName,
					SourceFile:   cfg.SourceFile,
					CheckID:      "IAM_WILDCARD",
					Severity:     "critical",
					Category:     "security",
					Message:      fmt.Sprintf("IAM action wildcard detected in function %s", cfg.FunctionName),
					Remediation:  "Replace wildcard actions with specific IAM actions following least-privilege principle",
					CurrentValue: "Action: *",
				})
				break
			}
		}

		for _, resource := range stmt.Resource {
			if resource == "*" {
				findings = append(findings, LambdaFinding{
					FunctionName: cfg.FunctionName,
					SourceFile:   cfg.SourceFile,
					CheckID:      "IAM_WILDCARD",
					Severity:     "critical",
					Category:     "security",
					Message:      fmt.Sprintf("IAM resource wildcard detected in function %s", cfg.FunctionName),
					Remediation:  "Scope resources to specific ARNs instead of using wildcard",
					CurrentValue: "Resource: *",
				})
				break
			}
		}
	}

	for _, arn := range cfg.ManagedPolicyARNs {
		findings = append(findings, LambdaFinding{
			FunctionName: cfg.FunctionName,
			SourceFile:   cfg.SourceFile,
			CheckID:      "MANAGED_POLICY",
			Severity:     "medium",
			Category:     "security",
			Message:      fmt.Sprintf("Managed policy %s attached to function %s", arn, cfg.FunctionName),
			Remediation:  "Review managed policy permissions and consider inline least-privilege policies",
			CurrentValue: arn,
		})
	}

	return findings
}
