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

// ============================================================================
// JavaScript/TypeScript Tests
// ============================================================================

func TestDetectJSN1QueryInForEach(t *testing.T) {
	source := `import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function getUsers(ids: number[]) {
  for (const id of ids) {
    await prisma.user.findUnique({ where: { id } });
  }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJS(source, "users.ts")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for N+1 query in forEach")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
			if p.FilePath != "users.ts" {
				t.Errorf("expected file_path 'users.ts', got '%s'", p.FilePath)
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

func TestDetectJSDynamoDBScanWithoutLimit(t *testing.T) {
	source := `import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({});

async function scanAllItems() {
  const result = await client.send(new ScanCommand({
    TableName: 'Users'
  }));
  return result.Items;
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJS(source, "dynamodb.ts")

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			found = true
			if p.FilePath != "dynamodb.ts" {
				t.Errorf("expected file_path 'dynamodb.ts', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternUnpaginatedScan to be detected")
	}
}

func TestDetectJSDynamoDBScanWithLimit(t *testing.T) {
	source := `import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({});

async function scanAllItems() {
  const result = await client.send(new ScanCommand({
    TableName: 'Users',
    Limit: 100
  }));
  return result.Items;
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJS(source, "dynamodb.ts")

	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			t.Error("should NOT detect unpaginated scan when Limit is present")
		}
	}
}

func TestDetectJSN1WithSequelize(t *testing.T) {
	source := `import { User } from './models';

async function getUserDetails(ids: number[]) {
  for (const id of ids) {
    await User.findByPk(id);
  }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJS(source, "sequelize.js")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for Sequelize N+1 query")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectJSCleanCodeNoPatterns(t *testing.T) {
	source := `import { UserService } from './services';

async function getUser(id: number) {
  const service = new UserService();
  return await service.findById(id);
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJS(source, "clean.ts")

	if len(patterns) != 0 {
		t.Errorf("expected no patterns in clean code, got %d", len(patterns))
	}
}

// ============================================================================
// Python Tests
// ============================================================================

func TestDetectPythonN1QueryInLoop(t *testing.T) {
	source := `from sqlalchemy.orm import Session

def get_users(db: Session, user_ids: list):
    for user_id in user_ids:
        user = db.query(User).filter(User.id == user_id).first()
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourcePython(source, "users.py")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for N+1 query in Python loop")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
			if p.FilePath != "users.py" {
				t.Errorf("expected file_path 'users.py', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectPythonDynamoDBScanWithoutLimit(t *testing.T) {
	source := `import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')

def scan_all():
    response = table.scan()
    return response['Items']
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourcePython(source, "dynamodb.py")

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			found = true
			if p.FilePath != "dynamodb.py" {
				t.Errorf("expected file_path 'dynamodb.py', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternUnpaginatedScan to be detected")
	}
}

func TestDetectPythonDynamoDBScanWithLimit(t *testing.T) {
	source := `import boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')

def scan_all():
    response = table.scan(Limit=100)
    return response['Items']
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourcePython(source, "dynamodb.py")

	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			t.Error("should NOT detect unpaginated scan when Limit is present")
		}
	}
}

func TestDetectPythonDjangoORMN1(t *testing.T) {
	source := `from myapp.models import Order

def get_order_items(order_ids):
    for order_id in order_ids:
        order = Order.objects.get(id=order_id)
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourcePython(source, "django.py")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for Django ORM N+1 query")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectPythonCleanCodeNoPatterns(t *testing.T) {
	source := `from services import UserService

def get_user(user_id):
    service = UserService()
    return service.find_by_id(user_id)
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourcePython(source, "clean.py")

	if len(patterns) != 0 {
		t.Errorf("expected no patterns in clean Python code, got %d", len(patterns))
	}
}

// ============================================================================
// Java Tests
// ============================================================================

func TestDetectJavaN1QueryInLoop(t *testing.T) {
	source := `import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public class UserService {
    public void getUsers(List<Long> ids) {
        for (Long id : ids) {
            User user = repository.findById(id).orElse(null);
        }
    }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJava(source, "UserService.java")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for N+1 query in Java loop")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
			if p.FilePath != "UserService.java" {
				t.Errorf("expected file_path 'UserService.java', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectJavaDynamoDBScanWithoutLimit(t *testing.T) {
	source := `import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;

public class UserRepository {
    public void scanAll() {
        ScanRequest request = ScanRequest.builder()
            .tableName("Users")
            .build();
        dynamoDbClient.scan(request);
    }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJava(source, "UserRepository.java")

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			found = true
			if p.FilePath != "UserRepository.java" {
				t.Errorf("expected file_path 'UserRepository.java', got '%s'", p.FilePath)
			}
		}
	}
	if !found {
		t.Error("expected PatternUnpaginatedScan to be detected")
	}
}

func TestDetectJavaDynamoDBScanWithLimit(t *testing.T) {
	source := `import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;

public class UserRepository {
    public void scanAll() {
        ScanRequest request = ScanRequest.builder()
            .tableName("Users")
            .limit(100)
            .build();
        dynamoDbClient.scan(request);
    }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJava(source, "UserRepository.java")

	for _, p := range patterns {
		if p.PatternType == PatternUnpaginatedScan {
			t.Error("should NOT detect unpaginated scan when Limit is present")
		}
	}
}

func TestDetectJavaJDBCN1(t *testing.T) {
	source := `import java.sql.*;

public class UserService {
    public void getUsers(int[] ids) throws SQLException {
        for (int id : ids) {
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setInt(1, id);
            ResultSet rs = ps.executeQuery();
        }
    }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJava(source, "UserService.java")

	if len(patterns) == 0 {
		t.Fatal("expected at least one pattern detected for JDBC N+1 query")
	}

	found := false
	for _, p := range patterns {
		if p.PatternType == PatternN1Query {
			found = true
		}
	}
	if !found {
		t.Error("expected PatternN1Query to be detected")
	}
}

func TestDetectJavaCleanCodeNoPatterns(t *testing.T) {
	source := `import com.example.UserService;

public class UserController {
    public User getUser(Long id) {
        UserService service = new UserService();
        return service.findById(id);
    }
}
`
	detector := NewPatternDetector()
	patterns := detector.DetectFromSourceJava(source, "UserController.java")

	if len(patterns) != 0 {
		t.Errorf("expected no patterns in clean Java code, got %d", len(patterns))
	}
}
