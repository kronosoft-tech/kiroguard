// Package finops implements the FinOps Guardrail for pre-deploy cost estimation.
package finops

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// PatternType represents a type of expensive cloud pattern detected in source code.
type PatternType string

const (
	// PatternN1Query indicates a database query inside a loop (N+1 pattern).
	PatternN1Query PatternType = "n_plus_1_query"
	// PatternNPlusOneQuery is an alias for PatternN1Query for readability.
	PatternNPlusOneQuery = PatternN1Query
	// PatternUnpaginatedScan indicates a DynamoDB Scan/Query without a Limit field.
	PatternUnpaginatedScan PatternType = "unpaginated_scan"
	// PatternLambdaNoMemory indicates a Lambda function creation without MemorySize.
	PatternLambdaNoMemory PatternType = "lambda_no_memory"
	// PatternLambdaNoTimeout indicates a Lambda function creation without Timeout.
	PatternLambdaNoTimeout PatternType = "lambda_no_timeout"
)

// DetectedPattern represents an expensive pattern found in source code.
type DetectedPattern struct {
	PatternType PatternType `json:"pattern_type"`
	FilePath    string      `json:"file_path"`
	LineNumber  int         `json:"line_number"`
	Details     string      `json:"details,omitempty"`
}

// PatternDetector analyzes Go source code to identify expensive cloud patterns.
type PatternDetector struct{}

// NewPatternDetector creates a new PatternDetector instance.
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{}
}

// dbCallNames contains function/method names that typically represent database queries.
var dbCallNames = []string{
	"Query", "QueryRow", "QueryContext", "QueryRowContext",
	"Exec", "ExecContext",
	"Find", "FindOne", "FindAll",
	"Get", "GetItem", "GetItems",
	"Select", "SelectContext",
	"Scan",
}

// DetectFromSource analyzes Go source code and returns detected expensive patterns.
func (d *PatternDetector) DetectFromSource(source string, filePath string) ([]DetectedPattern, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, source, parser.AllErrors)
	if err != nil {
		return nil, err
	}

	var patterns []DetectedPattern

	// Detect all patterns by walking the AST
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ForStmt:
			// Check for N+1 queries inside for loops
			found := d.detectDBCallsInBlock(fset, node.Body, filePath)
			patterns = append(patterns, found...)
		case *ast.RangeStmt:
			// Check for N+1 queries inside range loops
			found := d.detectDBCallsInBlock(fset, node.Body, filePath)
			patterns = append(patterns, found...)
		case *ast.CallExpr:
			// Check for unpaginated DynamoDB scans
			if p := d.detectUnpaginatedScan(fset, node, filePath); p != nil {
				patterns = append(patterns, *p)
			}
		case *ast.CompositeLit:
			// Check for Lambda CreateFunctionInput without MemorySize or Timeout
			found := d.detectLambdaMissingConfig(fset, node, filePath)
			patterns = append(patterns, found...)
		}
		return true
	})

	return patterns, nil
}

// detectDBCallsInBlock looks for database-like function calls within a block statement.
func (d *PatternDetector) detectDBCallsInBlock(fset *token.FileSet, block *ast.BlockStmt, filePath string) []DetectedPattern {
	var patterns []DetectedPattern
	if block == nil {
		return patterns
	}

	ast.Inspect(block, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		funcName := extractFuncName(call)
		if funcName == "" {
			return true
		}

		if isDBCall(funcName) {
			patterns = append(patterns, DetectedPattern{
				PatternType: PatternN1Query,
				FilePath:    filePath,
				LineNumber:  fset.Position(call.Pos()).Line,
				Details:     "Database call '" + funcName + "' inside a loop (N+1 query pattern)",
			})
		}
		return true
	})

	return patterns
}

// detectUnpaginatedScan checks if a call to Scan or Query on a DynamoDB-like
// object is missing a Limit field in its input struct.
func (d *PatternDetector) detectUnpaginatedScan(fset *token.FileSet, call *ast.CallExpr, filePath string) *DetectedPattern {
	funcName := extractFuncName(call)
	if funcName == "" {
		return nil
	}

	// Look for Scan or Query calls that might be DynamoDB operations
	if funcName != "Scan" && funcName != "Query" {
		return nil
	}

	// Check if any argument is a composite literal (struct) or address-of composite literal
	for _, arg := range call.Args {
		var lit *ast.CompositeLit

		switch a := arg.(type) {
		case *ast.CompositeLit:
			lit = a
		case *ast.UnaryExpr:
			// &ScanInput{...}
			if a.Op.String() == "&" {
				if cl, ok := a.X.(*ast.CompositeLit); ok {
					lit = cl
				}
			}
		}

		if lit == nil {
			continue
		}

		// Check if the struct type name suggests DynamoDB input
		typeName := extractTypeName(lit.Type)
		if !isDynamoDBInputType(typeName) {
			continue
		}

		// Check if Limit is present in the struct literal
		if !hasField(lit, "Limit") {
			return &DetectedPattern{
				PatternType: PatternUnpaginatedScan,
				FilePath:    filePath,
				LineNumber:  fset.Position(call.Pos()).Line,
				Details:     "DynamoDB " + funcName + " without Limit field (unpaginated)",
			}
		}
	}

	return nil
}

// detectLambdaMissingConfig checks if a CreateFunctionInput struct literal
// is missing MemorySize or Timeout fields.
func (d *PatternDetector) detectLambdaMissingConfig(fset *token.FileSet, lit *ast.CompositeLit, filePath string) []DetectedPattern {
	var patterns []DetectedPattern

	typeName := extractTypeName(lit.Type)
	if !isLambdaCreateType(typeName) {
		return patterns
	}

	hasMemory := hasField(lit, "MemorySize")
	hasTimeout := hasField(lit, "Timeout")

	if !hasMemory {
		patterns = append(patterns, DetectedPattern{
			PatternType: PatternLambdaNoMemory,
			FilePath:    filePath,
			LineNumber:  fset.Position(lit.Pos()).Line,
			Details:     "Lambda CreateFunctionInput without MemorySize configuration",
		})
	}

	if !hasTimeout {
		patterns = append(patterns, DetectedPattern{
			PatternType: PatternLambdaNoTimeout,
			FilePath:    filePath,
			LineNumber:  fset.Position(lit.Pos()).Line,
			Details:     "Lambda CreateFunctionInput without Timeout configuration",
		})
	}

	return patterns
}

// extractFuncName extracts the function or method name from a call expression.
func extractFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// extractTypeName extracts the type name from a composite literal type expression.
func extractTypeName(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return extractTypeName(t.X)
	}
	return ""
}

// hasField checks if a composite literal contains a field with the given name.
func hasField(lit *ast.CompositeLit, fieldName string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if ident, ok := kv.Key.(*ast.Ident); ok {
			if ident.Name == fieldName {
				return true
			}
		}
	}
	return false
}

// isDBCall checks if a function name matches known database call patterns.
func isDBCall(name string) bool {
	for _, dbName := range dbCallNames {
		if name == dbName {
			return true
		}
	}
	// Also check if the name contains common DB query indicators
	lower := strings.ToLower(name)
	if strings.Contains(lower, "query") || strings.Contains(lower, "findby") {
		return true
	}
	return false
}

// isDynamoDBInputType checks if a type name suggests a DynamoDB input struct.
func isDynamoDBInputType(name string) bool {
	dynamoTypes := []string{
		"ScanInput", "QueryInput",
		"dynamodb.ScanInput", "dynamodb.QueryInput",
		"types.ScanInput", "types.QueryInput",
	}
	for _, dt := range dynamoTypes {
		if name == dt {
			return true
		}
	}
	return false
}

// isLambdaCreateType checks if a type name suggests a Lambda function creation struct.
func isLambdaCreateType(name string) bool {
	lambdaTypes := []string{
		"CreateFunctionInput",
		"lambda.CreateFunctionInput",
		"types.CreateFunctionInput",
	}
	for _, lt := range lambdaTypes {
		if name == lt {
			return true
		}
	}
	return false
}
