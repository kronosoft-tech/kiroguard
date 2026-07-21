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
			Description: "Analyze a Go project's directory structure for architecture violations by parsing imports and evaluating them against configurable layer rules.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"directory_path": map[string]interface{}{
						"type":        "string",
						"description": "The root directory path of the Go project to analyze.",
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
			Description: "Detect expensive code patterns (N+1 queries, unpaginated DynamoDB scans, Lambda misconfigurations) and estimate their monthly AWS cost.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"source_code": map[string]interface{}{
						"type":        "string",
						"description": "The Go source code to analyze for expensive patterns.",
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
	}
}

// RegisterMCPHandlers registers the MCP protocol handlers (initialize and tools/list)
// with the given Dispatcher.
func RegisterMCPHandlers(d *Dispatcher) {
	d.Register("initialize", handleInitialize)
	d.Register("tools/list", handleToolsList)
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

// handleToolsList responds to the MCP "tools/list" method with all available tools.
func handleToolsList(_ context.Context, _ json.RawMessage) (interface{}, error) {
	return &ToolsListResult{
		Tools: mcpTools(),
	}, nil
}
