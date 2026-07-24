package piiguard

import (
	"testing"
)

func TestPatterns_Compile(t *testing.T) {
	if len(BuiltinPatterns) == 0 {
		t.Fatal("no builtin patterns")
	}
	for _, p := range BuiltinPatterns {
		if p.Name == "high_entropy_string" {
			continue // computed, not regex-based
		}
		if p.Regex == nil {
			t.Errorf("pattern %q has nil regex", p.Name)
		}
	}
}

func TestEmailPattern(t *testing.T) {
	if !emailRE.MatchString("user@example.com") {
		t.Error("should match user@example.com")
	}
	if !emailRE.MatchString("test.name+tag@sub.domain.co") {
		t.Error("should match complex email")
	}
	if emailRE.MatchString("not-an-email") {
		t.Error("should not match bare word")
	}
}

func TestCreditCardPattern(t *testing.T) {
	if !creditCardRE.MatchString("4111-1111-1111-1111") {
		t.Error("should match Visa format")
	}
	if !luhnCheck("4111111111111111") {
		t.Error("4111111111111111 should pass Luhn")
	}
	if luhnCheck("1234567890123456") {
		t.Error("1234567890123456 should fail Luhn")
	}
	if luhnCheck("") {
		t.Error("empty string should fail Luhn")
	}
	if luhnCheck("abc") {
		t.Error("non-digits should fail Luhn")
	}
}

func TestAWSAccessKey(t *testing.T) {
	if !awsAccessKeyRE.MatchString("AKIA1234567890123456") {
		t.Error("should match AKIA pattern")
	}
	if awsAccessKeyRE.MatchString("AKIA123456789012345") {
		t.Error("should not match 15-char key")
	}
}

func TestSSN(t *testing.T) {
	if !ssnRE.MatchString("123-45-6789") {
		t.Error("should match SSN")
	}
	if ssnRE.MatchString("123-45-678") {
		t.Error("should not match incomplete SSN")
	}
}

func TestJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9y1GvXx9B7ZQ"
	if !jwtTokenRE.MatchString(jwt) {
		t.Error("should match valid JWT")
	}
	if jwtTokenRE.MatchString("not.a.jwt") {
		t.Error("should not match non-JWT")
	}
}

func TestPrivateKey(t *testing.T) {
	if !privateKeyRE.MatchString("-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("should match RSA private key header")
	}
	if !privateKeyRE.MatchString("-----BEGIN EC PRIVATE KEY-----") {
		t.Error("should match EC private key header")
	}
	if privateKeyRE.MatchString("-----BEGIN CERTIFICATE-----") {
		t.Error("should not match certificate header")
	}
}

func TestGetPatterns_Filter(t *testing.T) {
	result := GetPatterns([]string{"email", "ssn"})
	if len(result) != 2 {
		t.Fatalf("got %d patterns, want 2", len(result))
	}
	if result[0].Name != "email" {
		t.Errorf("first = %q, want email", result[0].Name)
	}
	if result[1].Name != "ssn" {
		t.Errorf("second = %q, want ssn", result[1].Name)
	}
}

func TestGetPatterns_All(t *testing.T) {
	result := GetPatterns(nil)
	if len(result) != len(BuiltinPatterns) {
		t.Errorf("got %d patterns, want %d", len(result), len(BuiltinPatterns))
	}
}

func TestLuhnCheck_Valid(t *testing.T) {
	cases := []string{
		"4111111111111111",
		"5500000000000004",
		"340000000000009",
		"6011000000000004",
		"378282246310005",
	}
	for _, c := range cases {
		if !luhnCheck(c) {
			t.Errorf("expected valid Luhn: %s", c)
		}
	}
}

func TestLuhnCheck_Invalid(t *testing.T) {
	cases := []string{
		"1234567890123456",
		"4111111111111112",
		"1234567890123457",
	}
	for _, c := range cases {
		if luhnCheck(c) {
			t.Errorf("expected invalid Luhn: %s", c)
		}
	}
}

func TestPhonePattern(t *testing.T) {
	if !phoneRE.MatchString("+1 (555) 123-4567") {
		t.Error("should match US phone")
	}
	if !phoneRE.MatchString("+5491155551234") {
		t.Error("should match international phone")
	}
}

func TestGitHubToken(t *testing.T) {
	if !githubTokenRE.MatchString("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
		t.Error("should match ghp_ token")
	}
}

func TestIPAddress(t *testing.T) {
	if !ipAddressRE.MatchString("10.0.0.1") {
		t.Error("should match 10.x.x.x")
	}
	if !ipAddressRE.MatchString("192.168.1.1") {
		t.Error("should match 192.168.x.x")
	}
	if ipAddressRE.MatchString("8.8.8.8") {
		t.Error("should not match public DNS")
	}
}

func TestConnectionString(t *testing.T) {
	if !connectionStringRE.MatchString("jdbc:mysql://user:pass@localhost:3306/db") {
		t.Error("should match JDBC connection string")
	}
	if !connectionStringRE.MatchString("mongodb://admin:secret@cluster.mongodb.net:27017") {
		t.Error("should match MongoDB connection string")
	}
}
