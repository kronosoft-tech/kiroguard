package cleanarch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/luiferdev/kiroguard/internal/rpc"
)

// CleanArchInput represents the input parameters for the cleanarch/analyze tool.
type CleanArchInput struct {
	DirectoryPath string `json:"directory_path"`
	RulesFile     string `json:"rules_file,omitempty"`
}

// CleanArchOutput represents the output of the cleanarch/analyze tool.
type CleanArchOutput struct {
	Violations []ArchViolation `json:"violations"`
	TotalEdges int             `json:"total_edges"`
	Message    string          `json:"message"`
}

// CleanArchHandler wires together AST analysis, rule evaluation, and warning
// formatting to provide the complete Clean-Arch MCP tool.
// This handler is READ-ONLY: it never writes, modifies, or deletes any files.
type CleanArchHandler struct {
	defaultRules []Rule
}

// NewCleanArchHandler creates a new CleanArchHandler with the given default rules.
// If defaultRules is nil, DefaultRules() will be used when no rules file is specified.
func NewCleanArchHandler(defaultRules []Rule) *CleanArchHandler {
	if defaultRules == nil {
		defaultRules = DefaultRules()
	}
	return &CleanArchHandler{
		defaultRules: defaultRules,
	}
}

// Handle processes a cleanarch/analyze request.
// Flow:
//  1. Parse params as CleanArchInput
//  2. Validate directory_path is not empty
//  3. Load rules from rules_file if provided, otherwise use defaultRules
//  4. Call BuildImportGraph(directoryPath) to get edges
//  5. Call Evaluate(edges, rules) to get violations
//  6. Return CleanArchOutput with violations and summary
//
// This handler is READ-ONLY: it never writes, modifies, or deletes any files.
func (h *CleanArchHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input CleanArchInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if input.DirectoryPath == "" {
		return nil, fmt.Errorf("invalid params: directory_path is required")
	}

	// Step 1: Load rules
	rules := h.defaultRules
	if input.RulesFile != "" {
		loadedRules, err := LoadRules(input.RulesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules file: %w", err)
		}
		rules = loadedRules
	}

	// Step 2: Build import graph (read-only AST analysis)
	_, edges, err := BuildImportGraph(input.DirectoryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze directory: %w", err)
	}

	// Step 3: Evaluate edges against rules
	violations := Evaluate(edges, rules)

	// Step 4: Build message
	message := fmt.Sprintf("Analyzed %d import edges, found %d violation(s)", len(edges), len(violations))

	return &CleanArchOutput{
		Violations: violations,
		TotalEdges: len(edges),
		Message:    message,
	}, nil
}

// RegisterCleanArch registers the cleanarch/analyze tool handler with the RPC dispatcher.
func RegisterCleanArch(d *rpc.Dispatcher, handler *CleanArchHandler) {
	d.Register("cleanarch/analyze", handler.Handle)
}
