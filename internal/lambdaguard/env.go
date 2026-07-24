package lambdaguard

import (
	"fmt"
	"math"
	"regexp"
)

var (
	awsAccessKeyRE = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	emailRE        = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	genericKeyRE   = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret).{0,20}['"][A-Za-z0-9_\-\.]{16,64}['"]`)
	passwordRE     = regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{3,}['"]`)
	dynamicRefRE   = regexp.MustCompile(`\{\{resolve:(secretsmanager|ssm):`)
	cfnRefRE       = regexp.MustCompile(`!Ref\s+|!Sub\s+`)
)

var envValueThreshold = 20

func ScanEnvVars(cfg *LambdaConfig) []LambdaFinding {
	var findings []LambdaFinding

	for key, val := range cfg.Environment {
		if dynamicRefRE.MatchString(val) || cfnRefRE.MatchString(val) {
			continue
		}

		switch {
		case awsAccessKeyRE.MatchString(val):
			findings = append(findings, mkSecretFinding(cfg, key, "AWS_ACCESS_KEY", "critical"))
		case passwordRE.MatchString(val):
			findings = append(findings, mkSecretFinding(cfg, key, "PASSWORD", "critical"))
		case genericKeyRE.MatchString(val):
			findings = append(findings, mkSecretFinding(cfg, key, "API_KEY", "high"))
		case emailRE.MatchString(val):
			findings = append(findings, mkSecretFinding(cfg, key, "EMAIL", "low"))
		default:
			if len(val) > envValueThreshold && shannonEntropy(val) >= 4.5 {
				findings = append(findings, mkSecretFinding(cfg, key, "HIGH_ENTROPY", "medium"))
			}
		}
	}

	return findings
}

func mkSecretFinding(cfg *LambdaConfig, key, checkID, severity string) LambdaFinding {
	return LambdaFinding{
		FunctionName: cfg.FunctionName,
		SourceFile:   cfg.SourceFile,
		CheckID:      checkID,
		Severity:     severity,
		Category:     "security",
		Message:      fmt.Sprintf("Potential secret in environment variable %s of function %s", key, cfg.FunctionName),
		Remediation:  "Use AWS Secrets Manager or SSM Parameter Store instead of hardcoded values",
		CurrentValue: "****",
	}
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := len(s)
	for _, count := range freq {
		p := float64(count) / float64(length)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
