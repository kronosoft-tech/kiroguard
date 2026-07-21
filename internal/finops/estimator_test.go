package finops

import (
	"math"
	"testing"
)

func TestNewCostEstimator_DefaultRPH(t *testing.T) {
	// When defaultRPH is <= 0, it should default to 1000.
	e := NewCostEstimator(0)
	if e.defaultRPH != 1000 {
		t.Errorf("expected defaultRPH=1000, got %d", e.defaultRPH)
	}

	e = NewCostEstimator(-5)
	if e.defaultRPH != 1000 {
		t.Errorf("expected defaultRPH=1000 for negative input, got %d", e.defaultRPH)
	}
}

func TestNewCostEstimator_CustomRPH(t *testing.T) {
	e := NewCostEstimator(500)
	if e.defaultRPH != 500 {
		t.Errorf("expected defaultRPH=500, got %d", e.defaultRPH)
	}
}

func TestEstimate_UsesDefaultRPHWhenZero(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: PatternN1Query, FilePath: "main.go", LineNumber: 10}

	// requestsPerHour=0 should use defaultRPH
	result := e.Estimate(pattern, 0)
	expected := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD != expected.MonthlyCostUSD {
		t.Errorf("expected cost=%.2f when rph=0, got %.2f", expected.MonthlyCostUSD, result.MonthlyCostUSD)
	}
}

func TestEstimate_NPlusOneQuery_PositiveCost(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: PatternN1Query, FilePath: "service.go", LineNumber: 42}

	result := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD <= 0 {
		t.Errorf("expected positive cost for N+1 query, got %.2f", result.MonthlyCostUSD)
	}
	if result.PatternType != PatternN1Query {
		t.Errorf("expected pattern_type=%q, got %q", PatternN1Query, result.PatternType)
	}
	if result.Formula == "" {
		t.Error("expected non-empty formula")
	}
}

func TestEstimate_UnpaginatedScan_PositiveCost(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: PatternUnpaginatedScan, FilePath: "repo.go", LineNumber: 15}

	result := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD <= 0 {
		t.Errorf("expected positive cost for unpaginated scan, got %.2f", result.MonthlyCostUSD)
	}
	if result.PatternType != PatternUnpaginatedScan {
		t.Errorf("expected pattern_type=%q, got %q", PatternUnpaginatedScan, result.PatternType)
	}
	if result.Formula == "" {
		t.Error("expected non-empty formula")
	}
}

func TestEstimate_LambdaNoMemory_PositiveCost(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: PatternLambdaNoMemory, FilePath: "infra.tf", LineNumber: 3}

	result := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD <= 0 {
		t.Errorf("expected positive cost for lambda no memory, got %.2f", result.MonthlyCostUSD)
	}
	if result.PatternType != PatternLambdaNoMemory {
		t.Errorf("expected pattern_type=%q, got %q", PatternLambdaNoMemory, result.PatternType)
	}
	if result.Formula == "" {
		t.Error("expected non-empty formula")
	}
}

func TestEstimate_LambdaNoTimeout_PositiveCost(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: PatternLambdaNoTimeout, FilePath: "deploy.go", LineNumber: 88}

	result := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD <= 0 {
		t.Errorf("expected positive cost for lambda no timeout, got %.2f", result.MonthlyCostUSD)
	}
	if result.PatternType != PatternLambdaNoTimeout {
		t.Errorf("expected pattern_type=%q, got %q", PatternLambdaNoTimeout, result.PatternType)
	}
	if result.Formula == "" {
		t.Error("expected non-empty formula")
	}
}

func TestEstimate_Deterministic(t *testing.T) {
	e := NewCostEstimator(1000)
	patterns := []PatternType{
		PatternN1Query,
		PatternUnpaginatedScan,
		PatternLambdaNoMemory,
		PatternLambdaNoTimeout,
	}

	for _, pt := range patterns {
		pattern := DetectedPattern{PatternType: pt, FilePath: "test.go", LineNumber: 1}
		first := e.Estimate(pattern, 500)
		second := e.Estimate(pattern, 500)

		if first.MonthlyCostUSD != second.MonthlyCostUSD {
			t.Errorf("pattern %s: non-deterministic cost: %.2f vs %.2f", pt, first.MonthlyCostUSD, second.MonthlyCostUSD)
		}
		if first.Formula != second.Formula {
			t.Errorf("pattern %s: non-deterministic formula: %q vs %q", pt, first.Formula, second.Formula)
		}
	}
}

func TestEstimate_CostIncreasesWithRPH(t *testing.T) {
	e := NewCostEstimator(1000)
	patterns := []PatternType{
		PatternN1Query,
		PatternUnpaginatedScan,
		PatternLambdaNoMemory,
		PatternLambdaNoTimeout,
	}

	for _, pt := range patterns {
		pattern := DetectedPattern{PatternType: pt, FilePath: "test.go", LineNumber: 1}
		lowRPH := e.Estimate(pattern, 100)
		highRPH := e.Estimate(pattern, 10000)

		if highRPH.MonthlyCostUSD <= lowRPH.MonthlyCostUSD {
			t.Errorf("pattern %s: cost should increase with RPH (low=%.2f, high=%.2f)",
				pt, lowRPH.MonthlyCostUSD, highRPH.MonthlyCostUSD)
		}
	}
}

func TestEstimate_CostProportionalToRPH(t *testing.T) {
	e := NewCostEstimator(1000)
	patterns := []PatternType{
		PatternN1Query,
		PatternUnpaginatedScan,
		PatternLambdaNoMemory,
		PatternLambdaNoTimeout,
	}

	for _, pt := range patterns {
		pattern := DetectedPattern{PatternType: pt, FilePath: "test.go", LineNumber: 1}
		result1 := e.Estimate(pattern, 1000)
		result2 := e.Estimate(pattern, 2000)

		// Cost should approximately double when RPH doubles (allowing for rounding).
		ratio := result2.MonthlyCostUSD / result1.MonthlyCostUSD
		if math.Abs(ratio-2.0) > 0.1 {
			t.Errorf("pattern %s: expected cost to double with 2x RPH, ratio=%.4f", pt, ratio)
		}
	}
}

func TestEstimate_UnknownPattern(t *testing.T) {
	e := NewCostEstimator(1000)
	pattern := DetectedPattern{PatternType: "unknown_pattern", FilePath: "x.go", LineNumber: 1}

	result := e.Estimate(pattern, 1000)

	if result.MonthlyCostUSD != 0 {
		t.Errorf("expected zero cost for unknown pattern, got %.2f", result.MonthlyCostUSD)
	}
	if result.PatternType != "unknown_pattern" {
		t.Errorf("expected pattern_type=%q, got %q", PatternType("unknown_pattern"), result.PatternType)
	}
}

func TestEstimate_FormulaValues(t *testing.T) {
	e := NewCostEstimator(1000)

	// N+1 query: 100 × 1000 × 730 × 0.000001 = 73.0
	pattern := DetectedPattern{PatternType: PatternN1Query}
	result := e.Estimate(pattern, 1000)
	if result.MonthlyCostUSD != 73.0 {
		t.Errorf("N+1 query cost: expected 73.00, got %.2f", result.MonthlyCostUSD)
	}

	// Unpaginated scan: 10000 × 1000 × 730 × 0.0000025 = 18250.0
	pattern = DetectedPattern{PatternType: PatternUnpaginatedScan}
	result = e.Estimate(pattern, 1000)
	if result.MonthlyCostUSD != 18250.0 {
		t.Errorf("Unpaginated scan cost: expected 18250.00, got %.2f", result.MonthlyCostUSD)
	}

	// Lambda no memory: 256 × 1000 × 730 × 0.0000000163 = 3.05 (approx)
	pattern = DetectedPattern{PatternType: PatternLambdaNoMemory}
	result = e.Estimate(pattern, 1000)
	expected := math.Round(256.0*1000.0*730.0*0.0000000163*100) / 100
	if result.MonthlyCostUSD != expected {
		t.Errorf("Lambda no memory cost: expected %.2f, got %.2f", expected, result.MonthlyCostUSD)
	}

	// Lambda no timeout: 1000 × 730 × 0.05 × 0.0000166667 = 0.61 (approx)
	pattern = DetectedPattern{PatternType: PatternLambdaNoTimeout}
	result = e.Estimate(pattern, 1000)
	expected = math.Round(1000.0*730.0*0.05*0.0000166667*100) / 100
	if result.MonthlyCostUSD != expected {
		t.Errorf("Lambda no timeout cost: expected %.2f, got %.2f", expected, result.MonthlyCostUSD)
	}
}
