package rpc

import (
	"context"
	"encoding/json"
	"testing"
)

func TestHandleInitialize(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`1`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Verify protocol version
	if result.ProtocolVersion != MCPProtocolVersion {
		t.Errorf("expected protocolVersion %q, got %q", MCPProtocolVersion, result.ProtocolVersion)
	}

	// Verify server info
	if result.ServerInfo.Name != "kiroguard" {
		t.Errorf("expected server name %q, got %q", "kiroguard", result.ServerInfo.Name)
	}
	if result.ServerInfo.Version != "0.1.0" {
		t.Errorf("expected server version %q, got %q", "0.1.0", result.ServerInfo.Version)
	}

	// Verify capabilities include tools
	if result.Capabilities.Tools == nil {
		t.Fatal("expected tools capability to be present")
	}
}

func TestHandleInitialize_WithParams(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`2`)
	params := json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{}}`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success even with params, got error: %v", resp.Error)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result.ProtocolVersion != MCPProtocolVersion {
		t.Errorf("expected protocolVersion %q, got %q", MCPProtocolVersion, result.ProtocolVersion)
	}
}

func TestHandleToolsList(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`3`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/list",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	// Verify exactly 7 tools are returned
	if len(result.Tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(result.Tools))
	}

	// Verify the expected tool names
	expectedNames := map[string]bool{
		"envguard/scan":     true,
		"vulnscanner/scan":  true,
		"cleanarch/analyze": true,
		"finops/analyze":    true,
		"lambdaguard/analyze": true,
		"iamguard/analyze":  true,
		"piiguard/scan":     true,
	}

	for _, tool := range result.Tools {
		if !expectedNames[tool.Name] {
			t.Errorf("unexpected tool name: %q", tool.Name)
		}
		delete(expectedNames, tool.Name)

		// Every tool must have a non-empty description
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}

		// Every tool must have an input schema
		if tool.InputSchema == nil {
			t.Errorf("tool %q has nil input schema", tool.Name)
		}
	}

	// Verify we found all expected tools
	for name := range expectedNames {
		t.Errorf("missing expected tool: %q", name)
	}
}

func TestHandleToolsList_SchemaStructure(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`4`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/list",
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}

	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	for _, tool := range result.Tools {
		// Marshal and re-parse the schema to check JSON Schema structure
		schemaBytes, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("failed to marshal schema for tool %q: %v", tool.Name, err)
		}

		var schema map[string]interface{}
		if err := json.Unmarshal(schemaBytes, &schema); err != nil {
			t.Fatalf("schema for tool %q is not a valid JSON object: %v", tool.Name, err)
		}

		// Verify schema has "type": "object"
		if schema["type"] != "object" {
			t.Errorf("tool %q schema type should be \"object\", got %v", tool.Name, schema["type"])
		}

		// Verify schema has "properties"
		properties, ok := schema["properties"]
		if !ok || properties == nil {
			t.Errorf("tool %q schema should have properties", tool.Name)
		}

		// Verify schema has "required" array
		required, ok := schema["required"]
		if !ok || required == nil {
			t.Errorf("tool %q schema should have required array", tool.Name)
		}
	}
}

func TestHandleToolsList_EnvguardSchema(t *testing.T) {
	tools := mcpTools()

	var envguardTool *Tool
	for i := range tools {
		if tools[i].Name == "envguard/scan" {
			envguardTool = &tools[i]
			break
		}
	}

	if envguardTool == nil {
		t.Fatal("envguard/scan tool not found")
	}

	schemaBytes, err := json.Marshal(envguardTool.InputSchema)
	if err != nil {
		t.Fatalf("failed to marshal schema: %v", err)
	}

	var schema map[string]interface{}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}

	properties := schema["properties"].(map[string]interface{})

	// Verify "diff" property exists
	if _, ok := properties["diff"]; !ok {
		t.Error("envguard/scan schema missing 'diff' property")
	}

	// Verify "file_path" property exists
	if _, ok := properties["file_path"]; !ok {
		t.Error("envguard/scan schema missing 'file_path' property")
	}

	// Verify "diff" is required
	required := schema["required"].([]interface{})
	found := false
	for _, r := range required {
		if r == "diff" {
			found = true
			break
		}
	}
	if !found {
		t.Error("envguard/scan schema should require 'diff'")
	}
}

func TestMCPTools_Count(t *testing.T) {
	tools := mcpTools()
	if len(tools) != 7 {
		t.Errorf("expected 7 MCP tools, got %d", len(tools))
	}
}

func TestHandleToolsCall_Success(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	// Register a test tool handler
	d.Register("test/tool", func(ctx context.Context, params json.RawMessage) (interface{}, error) {
		return "tool executed successfully", nil
	})

	id := json.RawMessage(`10`)
	params := json.RawMessage(`{"name":"test/tool","arguments":{"key":"value"}}`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/call",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success, got error: %v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("expected non-nil result")
	}

	var result ToolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}
	if result.Content[0].Type != "text" {
		t.Errorf("expected content type 'text', got %q", result.Content[0].Type)
	}
	if result.Content[0].Text != "tool executed successfully" {
		t.Errorf("unexpected text: %q", result.Content[0].Text)
	}
	if result.IsError {
		t.Error("expected isError=false")
	}
}

func TestHandleToolsCall_UnknownTool(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`11`)
	params := json.RawMessage(`{"name":"unknown/tool","arguments":{}}`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/call",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error != nil {
		t.Fatalf("expected success response (tool error), got RPC error: %v", resp.Error)
	}

	var result ToolCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if !result.IsError {
		t.Error("expected isError=true for unknown tool")
	}
}

func TestHandleToolsCall_EmptyName(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`12`)
	params := json.RawMessage(`{"name":"","arguments":{}}`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/call",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for empty tool name")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("expected InvalidParams error, got code %d", resp.Error.Code)
	}
}

func TestHandleToolsCall_InvalidParams(t *testing.T) {
	d := NewDispatcher()
	RegisterMCPHandlers(d)

	id := json.RawMessage(`13`)
	params := json.RawMessage(`{invalid json}`)
	req := &Request{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/call",
		Params:  params,
	}

	resp := d.Dispatch(context.Background(), req)
	if resp.Error == nil {
		t.Fatal("expected error for invalid params")
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Errorf("expected InvalidParams error, got code %d", resp.Error.Code)
	}
}

func TestInitializeResult_JSONSerialization(t *testing.T) {
	result := &InitializeResult{
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
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal InitializeResult: %v", err)
	}

	var parsed InitializeResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal InitializeResult: %v", err)
	}

	if parsed.ProtocolVersion != result.ProtocolVersion {
		t.Errorf("round-trip protocolVersion mismatch: %q vs %q", parsed.ProtocolVersion, result.ProtocolVersion)
	}
	if parsed.ServerInfo.Name != result.ServerInfo.Name {
		t.Errorf("round-trip server name mismatch: %q vs %q", parsed.ServerInfo.Name, result.ServerInfo.Name)
	}
	if parsed.ServerInfo.Version != result.ServerInfo.Version {
		t.Errorf("round-trip server version mismatch: %q vs %q", parsed.ServerInfo.Version, result.ServerInfo.Version)
	}
	if parsed.Capabilities.Tools == nil {
		t.Error("round-trip lost tools capability")
	}

	// Verify the JSON has expected field names
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse as generic map: %v", err)
	}
	if _, ok := raw["protocolVersion"]; !ok {
		t.Error("JSON missing 'protocolVersion' field")
	}
	if _, ok := raw["capabilities"]; !ok {
		t.Error("JSON missing 'capabilities' field")
	}
	if _, ok := raw["serverInfo"]; !ok {
		t.Error("JSON missing 'serverInfo' field")
	}
}
