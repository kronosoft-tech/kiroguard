package piiguard

import "regexp"

var (
	emailRE           = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	phoneRE           = regexp.MustCompile(`(?:\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}|\d{1,3}[-.\s]\(?\d{1,4}\)?[-.\s]\d{1,4}[-.\s]\d{1,9})`)
	creditCardRE      = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	ssnRE             = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	awsAccessKeyRE    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	awsSecretKeyRE    = regexp.MustCompile(`(?i)aws(.{0,20})?(?:secret|key|access).{0,20}[A-Za-z0-9/+=]{40}`)
	githubTokenRE     = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,251}`)
	genericAPIKeyRE   = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret).{0,20}['\"][A-Za-z0-9_\-\.]{16,64}['\"]`)
	passwordFieldRE   = regexp.MustCompile(`(?i)["']?(?:password|passwd|pwd)["']?\s*[:=]\s*['\"][^'\"]{3,}['\"]`)
	privateKeyRE      = regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----`)
	jwtTokenRE        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	ipAddressRE       = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	connectionStringRE = regexp.MustCompile(`(?i)(?:jdbc|odbc|mongodb|postgresql|mysql)://[^\s]+`)
)

var BuiltinPatterns = []PIIPattern{
	{Name: "email", Severity: "low", Category: "pii", Regex: emailRE, Description: "RFC 5322 simplified email"},
	{Name: "phone", Severity: "low", Category: "pii", Regex: phoneRE, Description: "E.164 and common phone formats"},
	{Name: "credit_card", Severity: "critical", Category: "pii", Regex: creditCardRE, Description: "Luhn-validated credit card number"},
	{Name: "ssn", Severity: "high", Category: "pii", Regex: ssnRE, Description: "US Social Security Number"},
	{Name: "aws_access_key", Severity: "critical", Category: "credential", Regex: awsAccessKeyRE, Description: "AWS Access Key ID (AKIA)"},
	{Name: "aws_secret_key", Severity: "critical", Category: "credential", Regex: awsSecretKeyRE, Description: "AWS Secret Access Key"},
	{Name: "github_token", Severity: "critical", Category: "credential", Regex: githubTokenRE, Description: "GitHub personal access token"},
	{Name: "generic_api_key", Severity: "high", Category: "secret", Regex: genericAPIKeyRE, Description: "Generic API key or token"},
	{Name: "password_field", Severity: "critical", Category: "credential", Regex: passwordFieldRE, Description: "Password field assignment"},
	{Name: "private_key", Severity: "critical", Category: "secret", Regex: privateKeyRE, Description: "PEM-encoded private key"},
	{Name: "jwt_token", Severity: "high", Category: "secret", Regex: jwtTokenRE, Description: "JSON Web Token"},
	{Name: "ip_address", Severity: "medium", Category: "infra", Regex: ipAddressRE, Description: "Private IPv4 address"},
	{Name: "connection_string", Severity: "critical", Category: "credential", Regex: connectionStringRE, Description: "Database connection string with credentials"},
	{Name: "high_entropy_string", Severity: "medium", Category: "secret", Regex: nil, Description: "High-entropy string (Shannon ≥ 4.5)"},
}

func GetPatterns(names []string) []PIIPattern {
	if len(names) == 0 {
		out := make([]PIIPattern, len(BuiltinPatterns))
		copy(out, BuiltinPatterns)
		return out
	}

	lookup := make(map[string]bool, len(names))
	for _, n := range names {
		lookup[n] = true
	}

	var out []PIIPattern
	for _, p := range BuiltinPatterns {
		if lookup[p.Name] {
			out = append(out, p)
		}
	}
	return out
}

func luhnCheck(s string) bool {
	if len(s) == 0 {
		return false
	}
	var sum int
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == '-' || c == ' ' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
