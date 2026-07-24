package lambdaguard

import "testing"

func optimalConfig() *LambdaConfig {
	return &LambdaConfig{
		FunctionName:        "optimal-func",
		SourceFile:          "template.yaml",
		Runtime:             "nodejs20.x",
		Timeout:             30,
		MemorySize:          512,
		DLQTarget:           "arn:aws:sqs:us-east-1:123456789012:my-dlq",
		VPCConfig:           &VPCConfig{SubnetIDs: []string{"subnet-123"}, SecurityGroupIDs: []string{"sg-456"}},
		ReservedConcurrency: 5,
		TracingMode:         "Active",
		Description:         "My production function",
		Handler:             "index.handler",
		Architectures:       []string{"arm64"},
	}
}

func TestApplyBestPractices_AllPass(t *testing.T) {
	cfg := optimalConfig()
	findings := ApplyBestPractices(cfg, nil)
	if len(findings) != 0 {
		t.Errorf("got %d findings for optimal config, want 0: %+v", len(findings), findings)
	}
}

func TestApplyBestPractices_TimeoutTooLong(t *testing.T) {
	cfg := optimalConfig()
	cfg.Timeout = 910
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-1") {
		t.Error("expected LG-1 finding for timeout > 900")
	}
}

func TestApplyBestPractices_TimeoutDefault(t *testing.T) {
	cfg := optimalConfig()
	cfg.Timeout = 3
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-2") {
		t.Error("expected LG-2 finding for default timeout")
	}
}

func TestApplyBestPractices_MemoryTooHigh(t *testing.T) {
	cfg := optimalConfig()
	cfg.MemorySize = 4096
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-3") {
		t.Error("expected LG-3 finding for memory > 3008")
	}
}

func TestApplyBestPractices_MemoryTooLow(t *testing.T) {
	cfg := optimalConfig()
	cfg.MemorySize = 64
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-4") {
		t.Error("expected LG-4 finding for memory < 128")
	}
}

func TestApplyBestPractices_NoDLQ(t *testing.T) {
	cfg := optimalConfig()
	cfg.DLQTarget = ""
	cfg.Timeout = 120
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-5") {
		t.Error("expected LG-5 finding for no DLQ with timeout > 60")
	}
}

func TestApplyBestPractices_NoDLQShortTimeout(t *testing.T) {
	cfg := optimalConfig()
	cfg.DLQTarget = ""
	cfg.Timeout = 10
	findings := ApplyBestPractices(cfg, nil)
	if hasCheckID(findings, "LG-5") {
		t.Error("LG-5 should not fire when timeout <= 60")
	}
}

func TestApplyBestPractices_NoVPCForRDS(t *testing.T) {
	cfg := optimalConfig()
	cfg.VPCConfig = nil
	cfg.RoleStatements = []IAMStatement{
		{Effect: "Allow", Action: []string{"rds:DescribeDBInstances"}, Resource: []string{"*"}},
	}
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-6") {
		t.Error("expected LG-6 finding for no VPC with RDS permissions")
	}
}

func TestApplyBestPractices_NoReservedConcurrency(t *testing.T) {
	cfg := optimalConfig()
	cfg.ReservedConcurrency = -1
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-7") {
		t.Error("expected LG-7 finding for no reserved concurrency")
	}
}

func TestApplyBestPractices_RuntimeEOL(t *testing.T) {
	cfg := optimalConfig()
	cfg.Runtime = "nodejs12.x"
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-8") {
		t.Error("expected LG-8 finding for EOL runtime")
	}
}

func TestApplyBestPractices_TracingNotActive(t *testing.T) {
	cfg := optimalConfig()
	cfg.TracingMode = "PassThrough"
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-9") {
		t.Error("expected LG-9 finding for tracing not Active")
	}
}

func TestApplyBestPractices_NoDescription(t *testing.T) {
	cfg := optimalConfig()
	cfg.Description = ""
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-10") {
		t.Error("expected LG-10 finding for no description")
	}
}

func TestApplyBestPractices_LatestAlias(t *testing.T) {
	cfg := optimalConfig()
	cfg.Handler = "index.handler$LATEST"
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-11") {
		t.Error("expected LG-11 finding for $LATEST alias")
	}
}

func TestApplyBestPractices_BothArchitectures(t *testing.T) {
	cfg := optimalConfig()
	cfg.Architectures = []string{"x86_64", "arm64"}
	findings := ApplyBestPractices(cfg, nil)
	if !hasCheckID(findings, "LG-12") {
		t.Error("expected LG-12 finding for both architectures")
	}
}

func TestApplyBestPractices_FilterByCheckIDs(t *testing.T) {
	cfg := optimalConfig()
	cfg.Timeout = 910 // triggers LG-1
	cfg.Runtime = "nodejs12.x" // triggers LG-8

	findings := ApplyBestPractices(cfg, []string{"LG-1"})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].CheckID != "LG-1" {
		t.Errorf("CheckID = %q, want LG-1", findings[0].CheckID)
	}
}

func TestApplyBestPractices_MultipleFindings(t *testing.T) {
	cfg := optimalConfig()
	cfg.Timeout = 3    // LG-2
	cfg.MemorySize = 64 // LG-4
	cfg.Description = "" // LG-10

	findings := ApplyBestPractices(cfg, nil)
	if len(findings) < 3 {
		t.Errorf("got %d findings, want at least 3", len(findings))
	}
}

func hasCheckID(findings []LambdaFinding, checkID string) bool {
	for _, f := range findings {
		if f.CheckID == checkID {
			return true
		}
	}
	return false
}
