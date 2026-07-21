package finops

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/luiferdev/kiroguard/internal/llm"
	"github.com/luiferdev/kiroguard/internal/rpc"
)

// FinOpsInput represents the input parameters for the finops/analyze tool.
type FinOpsInput struct {
	SourceCode      string `json:"source_code"`
	FilePath        string `json:"file_path"`
	RequestsPerHour int    `json:"requests_per_hour,omitempty"`
}

// CostFinding represents a single cost-related finding with estimation details.
type CostFinding struct {
	PatternType   string  `json:"pattern_type"`
	FilePath      string  `json:"file_path"`
	LineNumber    int     `json:"line_number"`
	EstimatedCost float64 `json:"estimated_monthly_cost_usd"`
	Explanation   string  `json:"explanation"`
	Formula       string  `json:"formula"`
}

// FinOpsOutput represents the output of the finops/analyze tool.
type FinOpsOutput struct {
	Findings  []CostFinding `json:"findings"`
	TotalCost float64       `json:"total_estimated_monthly_cost_usd"`
	Message   string        `json:"message"`
}

// FinOpsHandler wires together pattern detection, cost estimation, and LLM explanation
// to provide the complete FinOps Guardrail MCP tool.
type FinOpsHandler struct {
	detector  *PatternDetector
	estimator *CostEstimator
	llm       llm.LLMBackend // may be nil
}

// NewFinOpsHandler creates a new FinOpsHandler with the given components.
// The llmBackend parameter may be nil, in which case heuristic messages are used.
func NewFinOpsHandler(detector *PatternDetector, estimator *CostEstimator, llmBackend llm.LLMBackend) *FinOpsHandler {
	return &FinOpsHandler{
		detector:  detector,
		estimator: estimator,
		llm:       llmBackend,
	}
}

// Handle processes a finops/analyze request.
// Flow:
//  1. Parse params and validate source_code is not empty
//  2. Call detector.DetectFromSource(source, filePath)
//  3. For each pattern, call estimator.Estimate(pattern, requestsPerHour)
//  4. If LLM available, generate explanations; otherwise use heuristic messages
//  5. Sum all costs into TotalCost
func (h *FinOpsHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input FinOpsInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if input.SourceCode == "" {
		return nil, fmt.Errorf("invalid params: source_code is required")
	}

	// Step 1: Detect expensive patterns
	patterns, err := h.detector.DetectFromSource(input.SourceCode, input.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze source: %w", err)
	}

	// Step 2: Estimate costs and build findings
	var findings []CostFinding
	var totalCost float64

	for _, pattern := range patterns {
		estimate := h.estimator.Estimate(pattern, input.RequestsPerHour)

		explanation := h.generateExplanation(ctx, pattern, estimate, input.RequestsPerHour)

		finding := CostFinding{
			PatternType:   string(pattern.PatternType),
			FilePath:      pattern.FilePath,
			LineNumber:    pattern.LineNumber,
			EstimatedCost: estimate.MonthlyCostUSD,
			Explanation:   explanation,
			Formula:       estimate.Formula,
		}

		findings = append(findings, finding)
		totalCost += estimate.MonthlyCostUSD
	}

	totalCost = roundTo2Decimals(totalCost)

	message := fmt.Sprintf("Analyzed source, found %d expensive pattern(s) with total estimated cost of $%.2f/month", len(findings), totalCost)

	return &FinOpsOutput{
		Findings:  findings,
		TotalCost: totalCost,
		Message:   message,
	}, nil
}

// generateExplanation produces a human-readable cost explanation for a finding.
// If an LLM backend is available, it is used for richer explanations.
// Otherwise, a heuristic message with concrete dollar amounts is returned.
func (h *FinOpsHandler) generateExplanation(ctx context.Context, pattern DetectedPattern, estimate CostEstimate, requestsPerHour int) string {
	if requestsPerHour <= 0 {
		requestsPerHour = 1000
	}

	// Try LLM first if available
	if h.llm != nil {
		prompt := llm.Prompt{
			System: "template:finops_explanation",
			User: fmt.Sprintf("PatternType=%s\nFilePath=%s\nLineNumber=%d\nEstimatedCost=%.2f\nRequestsPerHour=%d",
				pattern.PatternType, pattern.FilePath, pattern.LineNumber, estimate.MonthlyCostUSD, requestsPerHour),
		}

		resp, err := h.llm.Complete(ctx, prompt)
		if err == nil && resp.Text != "" {
			return resp.Text
		}
		// On LLM failure, fall through to heuristic
	}

	// Heuristic fallback with concrete dollar amounts
	switch pattern.PatternType {
	case PatternN1Query:
		return fmt.Sprintf("This loop contains a database call that creates an N+1 query pattern. At %d requests/hr, this could cost ~$%.2f/month in unnecessary read operations.", requestsPerHour, estimate.MonthlyCostUSD)
	case PatternUnpaginatedScan:
		return fmt.Sprintf("This DynamoDB scan has no Limit field and will read all items in the table. At %d requests/hr, this could cost ~$%.2f/month in read capacity.", requestsPerHour, estimate.MonthlyCostUSD)
	case PatternLambdaNoMemory:
		return fmt.Sprintf("This Lambda function has no MemorySize configured and will default to a potentially over-provisioned value. At %d requests/hr, the excess memory could cost ~$%.2f/month.", requestsPerHour, estimate.MonthlyCostUSD)
	case PatternLambdaNoTimeout:
		return fmt.Sprintf("This Lambda function has no Timeout configured, risking runaway executions. At %d requests/hr, potential runaway costs could reach ~$%.2f/month.", requestsPerHour, estimate.MonthlyCostUSD)
	default:
		return fmt.Sprintf("Expensive pattern detected. Estimated cost: ~$%.2f/month at %d requests/hr.", estimate.MonthlyCostUSD, requestsPerHour)
	}
}

// RegisterFinOps registers the finops/analyze tool handler with the RPC dispatcher.
func RegisterFinOps(d *rpc.Dispatcher, handler *FinOpsHandler) {
	d.Register("finops/analyze", handler.Handle)
}
