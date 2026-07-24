package lambdaguard

import "testing"

func TestAnalyzeIAM_InlineWildcardAction(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		RoleStatements: []IAMStatement{
			{Effect: "Allow", Action: []string{"*"}, Resource: []string{"arn:aws:s3:::my-bucket/*"}},
		},
	}

	findings := AnalyzeIAM(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard action")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
	if findings[0].CheckID != "IAM_WILDCARD" {
		t.Errorf("CheckID = %q, want IAM_WILDCARD", findings[0].CheckID)
	}
}

func TestAnalyzeIAM_InlineWildcardResource(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		RoleStatements: []IAMStatement{
			{Effect: "Allow", Action: []string{"s3:GetObject"}, Resource: []string{"*"}},
		},
	}

	findings := AnalyzeIAM(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard resource")
	}
	if findings[0].Severity != "critical" {
		t.Errorf("Severity = %q, want critical", findings[0].Severity)
	}
}

func TestAnalyzeIAM_ManagedPolicy(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		ManagedPolicyARNs: []string{
			"arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}

	findings := AnalyzeIAM(cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for managed policy")
	}
	if findings[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium", findings[0].Severity)
	}
	if findings[0].CheckID != "MANAGED_POLICY" {
		t.Errorf("CheckID = %q, want MANAGED_POLICY", findings[0].CheckID)
	}
}

func TestAnalyzeIAM_NoIssues(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
		RoleStatements: []IAMStatement{
			{Effect: "Allow", Action: []string{"s3:GetObject", "s3:PutObject"}, Resource: []string{"arn:aws:s3:::my-bucket/*"}},
		},
	}

	findings := AnalyzeIAM(cfg)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestAnalyzeIAM_EmptyRole(t *testing.T) {
	cfg := &LambdaConfig{
		FunctionName: "test-func",
		SourceFile:   "template.yaml",
	}

	findings := AnalyzeIAM(cfg)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
