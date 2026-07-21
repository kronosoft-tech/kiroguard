package finops

import (
	"testing"
)

func TestDetectN1QueryInForLoop(t *testing.T) {
	source := `package main

import "database/sql"

func getUsers(db *sql.DB, ids []int) {
	for i := 0; i < len(ids); i++ {
		db.QueryRow("SELECT * FROM users WHERE id = ?", ids[i])
	}
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for N+1 query in for loop")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
			if p.FilePath != "main.go" {
				t.Errorf("expected file_path 'main.go', got '%s'", p.FilePath)
			}
			if p.LineNumber <= 0 {
				t.Errorf("expected positive line number, got %d", p.LineNumber)
			}
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectN1QueryInRangeLoop(t *testing.T) {
	source := `package main

import "database/sql"

func getUsers(db *sql.DB, ids []int) {
	for _, id := range ids {
		db.Query("SELECT * FROM users WHERE id = ?", id)
	}
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "service.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for N+1 query in range loop")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
			if p.FilePath != "service.go" {
				t.Errorf("expected file_path 'service.go', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected in range loop")
	}
}

func TestDetectUnpaginatedScan(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/dynamodb"

func scanAll(client *dynamodb.Client) {
	client.Scan(&dynamodb.ScanInput{
		TableName: &tableName,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "repo.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern for unpaginated scan")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			found = true
			if p.FilePath != "repo.go" {
				t.Errorf("expected file_path 'repo.go', got '%s'", p.FilePath)
			}
			if p.LineNumber <= 0 {
				t.Errorf("expected positive line number, got %d", p.LineNumber)
			}
		}
	}
	if !found {
		t.Error("expected PatternUnpaginatedScan to be detected")
	}
}

func TestDetectUnpaginatedScanWithLimit(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/dynamodb"

func scanPaginated(client *dynamodb.Client) {
	client.Scan(&dynamodb.ScanInput{
		TableName: &tableName,
		Limit:     &limit,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "repo.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			t.Error("should NOT detect unpaginated scan when Limit is present")
		}
	}
}

func TestDetectLambdaNoMemory(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/lambda"

func createFunc(client *lambda.Client) {
	client.CreateFunction(&lambda.CreateFunctionInput{
		FunctionName: &name,
		Timeout:      &timeout,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "infra.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoMemory {
			found = true
			if p.FilePath != "infra.go" {
				t.Errorf("expected file_path 'infra.go', got '%s'", p.FilePath)
			}
			if p.LineNumber <= 0 {
				t.Errorf("expected positive line number, got %d", p.LineNumber)
			}
		}
	}
	if !found {
		t.Error("expected PatternLambdaNoMemory to be detected")
	}

	// Should NOT detect lambda_no_timeout since Timeout is present
	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoTimeout {
			t.Error("should NOT detect lambda_no_timeout when Timeout is present")
		}
	}
}

func TestDetectLambdaNoTimeout(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/lambda"

func createFunc(client *lambda.Client) {
	client.CreateFunction(&lambda.CreateFunctionInput{
		FunctionName: &name,
		MemorySize:   &memSize,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "infra.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoTimeout {
			found = true
			if p.FilePath != "infra.go" {
				t.Errorf("expected file_path 'infra.go', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternLambdaNoTimeout to be detected")
	}

	// Should NOT detect lambda_no_memory since MemorySize is present
	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoMemory {
			t.Error("should NOT detect lambda_no_memory when MemorySize is present")
		}
	}
}

func TestDetectLambdaBothMissing(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/lambda"

func createFunc(client *lambda.Client) {
	client.CreateFunction(&lambda.CreateFunctionInput{
		FunctionName: &name,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "deploy.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasNoMemory := false
	hasNoTimeout := false
	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoMemory {
			hasNoMemory = true
		}
		if p.PatternType == PatternLambdaNoTimeout {
			hasNoTimeout = true
		}
	}

	if !hasNoMemory {
		t.Error("expected PatternLambdaNoMemory when both are missing")
	}
	if !hasNoTimeout {
		t.Error("expected PatternLambdaNoTimeout when both are missing")
	}
}

func TestCleanCodeNoPatterns(t *testing.T) {
	source := `package main

import (
	"fmt"
	"strings"
)

func hello(name string) string {
	return fmt.Sprintf("Hello, %s!", strings.TrimSpace(name))
}

func sum(a, b int) int {
	return a + b
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "clean.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(patterns) != 0 {
		t.Errorf("expected no patterns in clean code, got %d: %+v", len(patterns), patterns)
	}
}

func TestDetectFromSourceInvalidSyntax(t *testing.T) {
	source := `this is not valid go code`

	detector := NewPatternDetector()
	_, err := detector.DetectFromSource(source, "bad.go")
	if err == nil {
		t.Error("expected error for invalid Go source")
	}
}

func TestDetectLocalScanNotDynamo(t *testing.T) {
	// A Scan call on a non-DynamoDB type should NOT be flagged
	source := `package main

func process() {
	scanner := bufio.NewScanner(file)
	scanner.Scan()
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "scanner.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			t.Error("should NOT flag non-DynamoDB Scan calls as unpaginated scan")
		}
	}
}

func TestDetectUnpaginatedQueryInput(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/dynamodb"

func queryAll(client *dynamodb.Client) {
	client.Query(&dynamodb.QueryInput{
		TableName: &tableName,
		KeyConditionExpression: &expr,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "query.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			found = true
		}
	}
	if !found {
		t.Error("expected PatternUnpaginatedScan for unpaginated DynamoDB Query")
	}
}

func TestDetectN1WithExecInLoop(t *testing.T) {
	source := `package main

import "database/sql"

func insertAll(db *sql.DB, items []Item) {
	for _, item := range items {
		db.Exec("INSERT INTO items (name) VALUES (?)", item.Name)
	}
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "repo.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
		}
	}
	if !found {
		t.Error("expected PatternN1Query for Exec inside range loop")
	}
}

func TestDetectLambdaFullyConfigured(t *testing.T) {
	source := `package main

import "github.com/aws/aws-sdk-go-v2/service/lambda"

func createFunc(client *lambda.Client) {
	client.CreateFunction(&lambda.CreateFunctionInput{
		FunctionName: &name,
		MemorySize:   &memSize,
		Timeout:      &timeout,
	})
}
`
	detector := NewPatternDetector()
	patterns, err := detector.DetectFromSource(source, "infra.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, p := range patterns {
		if p.PatternType == PatternLambdaNoMemory || p.PatternType == PatternLambdaNoTimeout {
			t.Errorf("should NOT detect lambda issues when fully configured, got: %s", p.PatternType)
		}
	}
}
