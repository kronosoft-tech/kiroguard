package rpc

import (
	"context"
	"encoding/json"
)

// MCP Protocol version supported by KiroGuard.
const MCPProtocolVersion = "2024-11-05"

// ServerInfo contains identification information about the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerCapabilities describes the capabilities supported by the server.
type ServerCapabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability describes the tools-related capabilities.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeResult is the response payload for the "initialize" MCP method.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Tool describes an MCP tool with its name, description, and input schema.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolsListResult is the response payload for the "tools/list" MCP method.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// mcpTools returns the list of all registered MCP tools with their input schemas.
func mcpTools() []Tool {
	return []Tool{
		{
			Name:        "envguard/scan",
			Description: "Scan diffs for leaked secrets (AWS keys, API tokens, PEM headers, database DSNs) and automatically migrate them to AWS Secrets Manager or SSM Parameter Store.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"diff": map[string]interface{}{
						"type":        "string",
						"description": "The diff content to scan for secrets.",
					},
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Optional file path for context in findings.",
					},
				},
				"required": []string{"diff"},
			},
		},
		{
			Name:        "vulnscanner/scan",
			Description: "Scan dependencies for known vulnerabilities by querying the OSV.dev database. Supports npm and pip ecosystems.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"manifest": map[string]interface{}{
						"type":        "string",
						"description": "The content of the package manifest file (package.json or requirements.txt).",
					},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "The package ecosystem: \"npm\" or \"pip\".",
						"enum":        []string{"npm", "pip"},
					},
				},
				"required": []string{"manifest", "ecosystem"},
			},
		},
		{
			Name:        "cleanarch/analyze",
			Description: "Analyze a project's directory structure for architecture violations by parsing imports and evaluating them against configurable layer rules. Supports Go, JavaScript, and TypeScript.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory_path": map[string]interface{}{
						"type":        "string",
						"description": "The root directory path of the project to analyze.",
					},
					"rules_file": map[string]interface{}{
						"type":        "string",
						"description": "Optional path to a YAML rules file. If not provided, default layered architecture rules are used.",
					},
				},
				"required": []string{"directory_path"},
			},
		},
		{
			Name:        "finops/analyze",
			Description: "Detect expensive code patterns (N+1 queries, unpaginated DynamoDB scans, Lambda misconfigurations) and estimate their monthly AWS cost. Supports Go, JavaScript, and TypeScript.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source_code": map[string]interface{}{
						"type":        "string",
						"description": "The source code to analyze for expensive patterns.",
					},
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "The file path of the source code being analyzed.",
					},
					"requests_per_hour": map[string]interface{}{
						"type":        "integer",
						"description": "Estimated execution frequency in requests per hour. Defaults to 1000 if not provided.",
					},
				},
				"required": []string{"source_code", "file_path"},
			},
		},
		{
			Name:        "lambdaguard/analyze",
			Description: "Analyze AWS Lambda configurations (SAM/CDK/Serverless YAML/JSON) for security and cost issues. Detects missing memory/timeout, excessive permissions, unencrypted env vars, and more.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory_path": map[string]interface{}{
						"type":        "string",
						"description": "Root directory to scan for Lambda configurations (SAM/CDK/Serverless YAML/JSON).",
					},
					"checks": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional list of specific check IDs to run.",
					},
					"severity_threshold": map[string]interface{}{
						"type":        "string",
						"description": "Minimum severity to include in results.",
						"enum":        []string{"low", "medium", "high", "critical"},
					},
				},
				"required": []string{"directory_path"},
			},
		},
		{
			Name:        "iamguard/analyze",
			Description: "Analyze AWS IAM policies for wildcard permissions and scan Go AWS SDK v2 calls for overly permissive IAM usage.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory_path": map[string]interface{}{
						"type":        "string",
						"description": "Root directory to scan for Go AWS SDK v2 calls and IaC wildcard IAM statements.",
					},
				},
				"required": []string{"directory_path"},
			},
		},
		{
			Name:        "piiguard/scan",
			Description: "Scan source code for PII patterns (emails, phone numbers, SSNs, credit cards, IP addresses) and detect high-entropy strings that may be secrets.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory_path": map[string]interface{}{
						"type":        "string",
						"description": "Root directory to scan for PII patterns.",
					},
					"severity_threshold": map[string]interface{}{
						"type":        "string",
						"description": "Minimum severity to report.",
						"enum":        []string{"low", "medium", "high", "critical"},
					},
					"patterns": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Optional subset of pattern names to scan for.",
					},
					"entropy_check": map[string]interface{}{
						"type":        "boolean",
						"description": "Whether to include high-entropy string detection (default true).",
					},
				},
				"required": []string{"directory_path"},
			},
		},
	}
}

// RegisterMCPHandlers registers the MCP protocol handlers (initialize, tools/list, and tools/call)
// with the given Dispatcher.
func RegisterMCPHandlers(d *Dispatcher) {
	d.Register("initialize", handleInitialize)
	d.Register("notifications/initialized", handleNotificationsInitialized)
	d.Register("ping", handlePing)
	d.Register("tools/list", handleToolsList)
	d.Register("tools/call", d.handleToolsCall)
}

// handleInitialize responds to the MCP "initialize" method with server info and capabilities.
func handleInitialize(_ context.Context, _ json.RawMessage) (interface{}, error) {
	return &InitializeResult{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities: ServerCapabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
		},
		ServerInfo: ServerInfo{
			Name:    "kiroguard",
			Version: "0.1.0",
		},
	}, nil
}

// handleNotificationsInitialized handles the "notifications/initialized" notification.
// This is sent by the client after receiving the initialize response.
func handleNotificationsInitialized(_ context.Context, _ json.RawMessage) (interface{}, error) {
	// Notifications don't return a result, but we return nil to indicate success
	return nil, nil
}

// handlePing handles the "ping" method for keepalive.
func handlePing(_ context.Context, _ json.RawMessage) (interface{}, error) {
	return map[string]interface{}{}, nil
}

// handleToolsList responds to the MCP "tools/list" method with all available tools.
func handleToolsList(_ context.Context, _ json.RawMessage) (interface{}, error) {
	return &ToolsListResult{
		Tools: mcpTools(),
	}, nil
}

// ToolCallParams represents the parameters for a "tools/call" MCP request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolCallResult is the response payload for the "tools/call" MCP method.
type ToolCallResult struct {
	Content []ToolCallContent `json:"content"`
	IsError bool              `json:"isError,omitempty"`
}

// ToolCallContent represents a single content item in a tool call result.
type ToolCallContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// handleToolsCall routes a "tools/call" request to the registered tool handler.
func (d *Dispatcher) handleToolsCall(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var callParams ToolCallParams
	if err := json.Unmarshal(params, &callParams); err != nil {
		return nil, NewValidationError("invalid tools/call params: " + err.Error())
	}

	if callParams.Name == "" {
		return nil, NewValidationError("tool name is required")
	}

	// Look up the registered handler for this tool name.
	d.mu.RLock()
	handler, ok := d.handlers[callParams.Name]
	d.mu.RUnlock()

	if !ok {
		return &ToolCallResult{
			Content: []ToolCallContent{
				{Type: "text", Text: "unknown tool: " + callParams.Name},
			},
			IsError: true,
		}, nil
	}

	// Invoke the tool handler with its arguments.
	result, err := handler(ctx, callParams.Arguments)
	if err != nil {
		return &ToolCallResult{
			Content: []ToolCallContent{
				{Type: "text", Text: err.Error()},
			},
			IsError: true,
		}, nil
	}

	// Marshal the result to text content.
	var text string
	switch v := result.(type) {
	case string:
		text = v
	default:
		data, marshalErr := json.Marshal(v)
		if marshalErr != nil {
			return nil, NewValidationError("failed to marshal tool result: " + marshalErr.Error())
		}
		text = string(data)
	}

	return &ToolCallResult{
		Content: []ToolCallContent{
			{Type: "text", Text: text},
		},
	}, nil
}
