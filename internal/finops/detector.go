// Package finops implements the FinOps Guardrail for pre-deploy cost estimation.
package finops

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
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

// ============================================================================
// JavaScript/TypeScript Support
// ============================================================================

// jsDBCallPatterns contains regex patterns for JS/TS ORM/database calls
var jsDBCallPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.(?:find|findOne|findAll|findById|findByPk|query|exec|scan|get|create|update|destroy)\s*\(`),
	regexp.MustCompile(`\.(?:execute|prepare|run|get|all)\s*\(`),
	regexp.MustCompile(`(?:prisma|sequelize|typeorm|mongoose|knex)\s*\.\s*\w+`),
}

// jsDynamoDBPatterns contains regex patterns for DynamoDB operations
var jsDynamoDBPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:dynamodb|docClient)\s*\.\s*(?:scan|query)\s*\(`),
	regexp.MustCompile(`new\s+ScanCommand\s*\(`),
	regexp.MustCompile(`new\s+QueryCommand\s*\(`),
	regexp.MustCompile(`\.scan\s*\(\s*\{`),
}

// jsLambdaPatterns contains regex patterns for Lambda function creation
var jsLambdaPatterns = []*regexp.Regexp{
	regexp.MustCompile(`new\s+Function\s*\(\s*\{`),
	regexp.MustCompile(`(?:runtime|memorySize|timeout)\s*:`),
}

// DetectFromSourceJS analyzes JavaScript/TypeScript source code and returns detected expensive patterns.
func (d *PatternDetector) DetectFromSourceJS(source string, filePath string) []DetectedPattern {
	var patterns []DetectedPattern
	lines := strings.Split(source, "\n")

	// Track if we're inside a loop
	inLoop := false
	loopDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := i + 1

		// Track loop nesting
		if isJSLoopStart(trimmed) {
			if loopDepth == 0 {
				inLoop = true
			}
			loopDepth++
		}
		if isJSLoopEnd(trimmed) {
			loopDepth--
			if loopDepth <= 0 {
				inLoop = false
				loopDepth = 0
			}
		}

		// N+1 query detection: DB call inside a loop
		if inLoop && hasJSDBCall(trimmed) {
			patterns = append(patterns, DetectedPattern{
				PatternType: PatternN1Query,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "Database call inside a loop (N+1 query pattern)",
			})
		}

		// Unpaginated DynamoDB scan detection
		if p := detectJSDynamoDBScan(trimmed, lines, i, filePath, lineNum); p != nil {
			patterns = append(patterns, *p)
		}
	}

	return patterns
}

// isJSLoopStart checks if a line starts a JS/TS loop
func isJSLoopStart(line string) bool {
	loopPatterns := []string{
		"for (", "for(", "forEach(", ".forEach(",
		"while (", "while(",
	}
	for _, p := range loopPatterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// isJSLoopEnd checks if a line ends a JS/TS loop (closing brace)
func isJSLoopEnd(line string) bool {
	return line == "}" || strings.HasPrefix(line, "}")
}

// hasJSDBCall checks if a line contains a JS/TS database call
func hasJSDBCall(line string) bool {
	for _, pattern := range jsDBCallPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

// detectJSDynamoDBScan detects unpaginated DynamoDB scans in JS/TS
func detectJSDynamoDBScan(line string, allLines []string, currentIdx int, filePath string, lineNum int) *DetectedPattern {
	for _, pattern := range jsDynamoDBPatterns {
		if pattern.MatchString(line) {
			// Check if Limit is present in the same line or nearby lines (look up to 5 lines ahead)
			if hasLimitInNearbyLines(allLines, currentIdx, 5) {
				return nil
			}
			return &DetectedPattern{
				PatternType: PatternUnpaginatedScan,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "DynamoDB scan/query without Limit parameter (unpaginated)",
			}
		}
	}
	return nil
}

// hasLimitInNearbyLines checks if a Limit/limit/maxResults/MaxResults field appears
// within a window of maxLookahead lines before and after startIdx.
func hasLimitInNearbyLines(lines []string, startIdx, maxLookahead int) bool {
	// Search backward from startIdx (for cases like Java builder pattern where
	// .limit() is set before the .scan() call)
	start := startIdx - maxLookahead
	if start < 0 {
		start = 0
	}
	// Search forward from startIdx
	end := startIdx + maxLookahead + 1
	if end > len(lines) {
		end = len(lines)
	}
	for i := start; i < end; i++ {
		l := lines[i]
		if strings.Contains(l, "Limit") || strings.Contains(l, "limit") ||
			strings.Contains(l, "maxResults") || strings.Contains(l, "MaxResults") {
			return true
		}
		// Stop looking forward if we hit a closing paren/brace that ends the object
		if i >= startIdx {
			trimmed := strings.TrimSpace(l)
			if trimmed == "}));" || trimmed == "}))" || trimmed == "});" || trimmed == "})" {
				break
			}
		}
	}
	return false
}

// ============================================================================
// Python Support
// ============================================================================

// pyDBCallPatterns contains regex patterns for Python ORM/database calls
var pyDBCallPatterns = []*regexp.Regexp{
	// SQLAlchemy
	regexp.MustCompile(`\.(?:query|filter|filter_by|get|all|first|count|scalar|execute)\s*\(`),
	// Django ORM
	regexp.MustCompile(`(?:objects\.\s*(?:filter|get|all|exclude|select_related|prefetch_related))\s*\(`),
	// Django raw queries
	regexp.MustCompile(`(?:cursor\.\s*(?:execute|fetchone|fetchall))\s*\(`),
	// psycopg2 / asyncpg
	regexp.MustCompile(`(?:await\s+)?(?:conn|connection|pool)\.\s*(?:fetch|execute|fetchrow|fetchval)\s*\(`),
	// MySQL/PostgreSQL connectors
	regexp.MustCompile(`(?:cursor\.\s*(?:execute|executemany|fetchone|fetchall))\s*\(`),
}

// pyDynamoDBPatterns contains regex patterns for Python DynamoDB operations
var pyDynamoDBPatterns = []*regexp.Regexp{
	// boto3 resource
	regexp.MustCompile(`(?:table|dynamodb)\s*\.\s*(?:scan|query)\s*\(`),
	// boto3 client
	regexp.MustCompile(`(?:client|dynamodb)\s*\.\s*(?:scan|query)\s*\(`),
	// aioboto3
	regexp.MustCompile(`await\s+\w+\.\s*(?:scan|query)\s*\(`),
}

// DetectFromSourcePython analyzes Python source code and returns detected expensive patterns.
func (d *PatternDetector) DetectFromSourcePython(source string, filePath string) []DetectedPattern {
	var patterns []DetectedPattern
	lines := strings.Split(source, "\n")

	// Track Python loops using a stack of indentation levels
	type loopEntry struct{ indent int }
	var loopStack []loopEntry

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := i + 1
		indent := pythonIndent(line)

		// Pop loops whose scope has ended (indent <= loop start indent)
		for len(loopStack) > 0 && indent <= loopStack[len(loopStack)-1].indent {
			loopStack = loopStack[:len(loopStack)-1]
		}

		// Push new loop if this line starts one
		if isPythonLoopStart(trimmed) {
			loopStack = append(loopStack, loopEntry{indent: indent})
		}

		// N+1 query detection: DB call inside a loop
		if len(loopStack) > 0 && hasPythonDBCall(trimmed) {
			patterns = append(patterns, DetectedPattern{
				PatternType: PatternN1Query,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "Database call inside a loop (N+1 query pattern)",
			})
		}

		// Unpaginated DynamoDB scan detection
		if p := detectPythonDynamoDBScan(trimmed, lines, i, filePath, lineNum); p != nil {
			patterns = append(patterns, *p)
		}
	}

	return patterns
}

// isPythonLoopStart checks if a line starts a Python loop
func isPythonLoopStart(line string) bool {
	return strings.HasPrefix(line, "for ") || strings.HasPrefix(line, "while ")
}

// pythonIndent returns the indentation level of a line in spaces (tabs = 4)
func pythonIndent(line string) int {
	indent := 0
	for _, ch := range line {
		if ch == ' ' {
			indent++
		} else if ch == '\t' {
			indent += 4
		} else {
			break
		}
	}
	return indent
}

// hasPythonDBCall checks if a line contains a Python database call
func hasPythonDBCall(line string) bool {
	for _, pattern := range pyDBCallPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

// detectPythonDynamoDBScan detects unpaginated DynamoDB scans in Python
func detectPythonDynamoDBScan(line string, allLines []string, currentIdx int, filePath string, lineNum int) *DetectedPattern {
	for _, pattern := range pyDynamoDBPatterns {
		if pattern.MatchString(line) {
			// Check if Limit is present in nearby lines
			if hasLimitInNearbyLines(allLines, currentIdx, 5) {
				return nil
			}
			return &DetectedPattern{
				PatternType: PatternUnpaginatedScan,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "DynamoDB scan/query without Limit parameter (unpaginated)",
			}
		}
	}
	return nil
}

// ============================================================================
// Java Support
// ============================================================================

// javaDBCallPatterns contains regex patterns for Java ORM/database calls
var javaDBCallPatterns = []*regexp.Regexp{
	// JPA/Hibernate
	regexp.MustCompile(`(?:entityManager|em|repository)\s*\.\s*(?:find|findBy|findAll|query|createQuery|createNativeQuery|getReference)\s*\(`),
	// Spring Data
	regexp.MustCompile(`(?:findAll|findById|findBy|count|exists|deleteById)\s*\(`),
	// JDBC
	regexp.MustCompile(`(?:statement|ps|rs)\s*\.\s*(?:executeQuery|execute|next|getString|getInt)\s*\(`),
	// MyBatis
	regexp.MustCompile(`(?:mapper|sqlSession)\s*\.\s*(?:select|insert|update|delete)\s*\(`),
}

// javaDynamoDBPatterns contains regex patterns for Java DynamoDB operations
var javaDynamoDBPatterns = []*regexp.Regexp{
	// AWS SDK v2
	regexp.MustCompile(`(?:dynamoDbClient|dynamodb)\s*\.\s*(?:scan|query)\s*\(`),
	regexp.MustCompile(`ScanRequest\.builder\s*\(\)|QueryRequest\.builder\s*\(\)`),
}

// DetectFromSourceJava analyzes Java source code and returns detected expensive patterns.
func (d *PatternDetector) DetectFromSourceJava(source string, filePath string) []DetectedPattern {
	var patterns []DetectedPattern
	lines := strings.Split(source, "\n")

	// Track if we're inside a loop
	inLoop := false
	loopDepth := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		lineNum := i + 1

		// Track loop nesting
		if isJavaLoopStart(trimmed) {
			if loopDepth == 0 {
				inLoop = true
			}
			loopDepth++
		}
		if isJavaLoopEnd(trimmed) {
			loopDepth--
			if loopDepth <= 0 {
				inLoop = false
				loopDepth = 0
			}
		}

		// N+1 query detection: DB call inside a loop
		if inLoop && hasJavaDBCall(trimmed) {
			patterns = append(patterns, DetectedPattern{
				PatternType: PatternN1Query,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "Database call inside a loop (N+1 query pattern)",
			})
		}

		// Unpaginated DynamoDB scan detection
		if p := detectJavaDynamoDBScan(trimmed, lines, i, filePath, lineNum); p != nil {
			patterns = append(patterns, *p)
		}
	}

	return patterns
}

// isJavaLoopStart checks if a line starts a Java loop
func isJavaLoopStart(line string) bool {
	return strings.HasPrefix(line, "for (") || strings.HasPrefix(line, "for(") ||
		strings.HasPrefix(line, "while (") || strings.HasPrefix(line, "while(")
}

// isJavaLoopEnd checks if a line ends a Java loop (closing brace)
func isJavaLoopEnd(line string) bool {
	return line == "}" || strings.HasPrefix(line, "}")
}

// hasJavaDBCall checks if a line contains a Java database call
func hasJavaDBCall(line string) bool {
	for _, pattern := range javaDBCallPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	return false
}

// detectJavaDynamoDBScan detects unpaginated DynamoDB scans in Java
func detectJavaDynamoDBScan(line string, allLines []string, currentIdx int, filePath string, lineNum int) *DetectedPattern {
	for _, pattern := range javaDynamoDBPatterns {
		if pattern.MatchString(line) {
			// Check if Limit is present in nearby lines
			if hasLimitInNearbyLines(allLines, currentIdx, 5) {
				return nil
			}
			return &DetectedPattern{
				PatternType: PatternUnpaginatedScan,
				FilePath:    filePath,
				LineNumber:  lineNum,
				Details:     "DynamoDB scan/query without Limit parameter (unpaginated)",
			}
		}
	}
	return nil
}
