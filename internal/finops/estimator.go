package finops

import (
	"fmt"
	"math"
)

const (
	// hoursPerMonth is the average hours per month (365*24/12).
	hoursPerMonth = 730

	// DynamoDB read unit cost per item.
	dynamoDBReadCostPerItem = 0.000001

	// Unpaginated scan cost per item (items × unit cost).
	unpaginatedScanCostPerItem = 0.0000025

	// Lambda cost per MB-second.
	lambdaMBSecondCost = 0.0000000163

	// Lambda cost per GB-second.
	lambdaGBSecondCost = 0.0000166667
)

// CostEstimate represents the result of a cost estimation for a detected pattern.
type CostEstimate struct {
	PatternType    PatternType `json:"pattern_type"`
	MonthlyCostUSD float64     `json:"monthly_cost_usd"`
	Formula        string      `json:"formula"`
}

// CostEstimator calculates estimated monthly costs for detected expensive patterns.
type CostEstimator struct {
	defaultRPH int // requests per hour, default 1000
}

// NewCostEstimator creates a new CostEstimator with the given default requests per hour.
// If defaultRPH is <= 0, it defaults to 1000.
func NewCostEstimator(defaultRPH int) *CostEstimator {
	if defaultRPH <= 0 {
		defaultRPH = 1000
	}
	return &CostEstimator{defaultRPH: defaultRPH}
}

// Estimate calculates the estimated monthly cost for a detected pattern.
// If requestsPerHour is 0, the estimator's defaultRPH is used.
func (e *CostEstimator) Estimate(pattern DetectedPattern, requestsPerHour int) CostEstimate {
	if requestsPerHour <= 0 {
		requestsPerHour = e.defaultRPH
	}

	rph := float64(requestsPerHour)

	switch pattern.PatternType {
	case PatternN1Query:
		return e.estimateNPlusOne(rph)
	case PatternUnpaginatedScan:
		return e.estimateUnpaginatedScan(rph)
	case PatternLambdaNoMemory:
		return e.estimateLambdaNoMemory(rph)
	case PatternLambdaNoTimeout:
		return e.estimateLambdaNoTimeout(rph)
	default:
		return CostEstimate{
			PatternType:    pattern.PatternType,
			MonthlyCostUSD: 0,
			Formula:        "unknown pattern type",
		}
	}
}

// estimateNPlusOne calculates cost for N+1 query pattern.
// Formula: 100 queries × rph × 730 hr/month × $0.000001/read
func (e *CostEstimator) estimateNPlusOne(rph float64) CostEstimate {
	queriesPerRequest := 100.0
	cost := queriesPerRequest * rph * hoursPerMonth * dynamoDBReadCostPerItem

	return CostEstimate{
		PatternType:    PatternN1Query,
		MonthlyCostUSD: roundTo2Decimals(cost),
		Formula:        fmt.Sprintf("100 queries × %.0f/hr × 730 hr/month × $0.000001/read", rph),
	}
}

// estimateUnpaginatedScan calculates cost for unpaginated DynamoDB scan pattern.
// Formula: 10000 items × rph × 730 hr/month × $0.0000025/item
func (e *CostEstimator) estimateUnpaginatedScan(rph float64) CostEstimate {
	itemsPerScan := 10000.0
	cost := itemsPerScan * rph * hoursPerMonth * unpaginatedScanCostPerItem

	return CostEstimate{
		PatternType:    PatternUnpaginatedScan,
		MonthlyCostUSD: roundTo2Decimals(cost),
		Formula:        fmt.Sprintf("10000 items × %.0f/hr × 730 hr/month × $0.0000025/item", rph),
	}
}

// estimateLambdaNoMemory calculates cost for Lambda without memory configuration.
// Assumes over-provisioned at default 512MB vs optimal 256MB (excess = 256MB).
// Formula: 256MB excess × rph × 730 hr/month × $0.0000000163/MB-s
func (e *CostEstimator) estimateLambdaNoMemory(rph float64) CostEstimate {
	excessMB := 256.0
	cost := excessMB * rph * hoursPerMonth * lambdaMBSecondCost

	return CostEstimate{
		PatternType:    PatternLambdaNoMemory,
		MonthlyCostUSD: roundTo2Decimals(cost),
		Formula:        fmt.Sprintf("256MB excess × %.0f/hr × 730 hr/month × $0.0000000163/MB-s", rph),
	}
}

// estimateLambdaNoTimeout calculates cost for Lambda without timeout configuration.
// Risk of runaway execution: rph × 730 hr/month × 5% risk × $0.0000166667/GB-s
func (e *CostEstimator) estimateLambdaNoTimeout(rph float64) CostEstimate {
	riskFactor := 0.05
	cost := rph * hoursPerMonth * riskFactor * lambdaGBSecondCost

	return CostEstimate{
		PatternType:    PatternLambdaNoTimeout,
		MonthlyCostUSD: roundTo2Decimals(cost),
		Formula:        fmt.Sprintf("%.0f/hr × 730 hr/month × 5%% risk × $0.0000166667/GB-s", rph),
	}
}

// roundTo2Decimals rounds a float64 to 2 decimal places.
func roundTo2Decimals(v float64) float64 {
	return math.Round(v*100) / 100
}
