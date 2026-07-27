package iamguard

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SDKUsage records a single AWS SDK method call site.
type SDKUsage struct {
	FilePath      string `json:"file_path"`
	LineNumber    int    `json:"line_number"`
	ServiceImport string `json:"service_import"`
	Service       string `json:"service"`
	Method        string `json:"method"`
	IAMAction     string `json:"iam_action"`
}

// AWSAction is a deduplicated IAM action with call-site count.
type AWSAction struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Count   int    `json:"count"`
}

// isAWSSDKImport checks if an import path is an AWS SDK v2 service package.
// Returns the service name (e.g. "s3") and true, or "" and false.
func isAWSSDKImport(path string) (service string, ok bool) {
	const prefix = "github.com/aws/aws-sdk-go-v2/service/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	svc := strings.TrimPrefix(path, prefix)
	if idx := strings.Index(svc, "/"); idx >= 0 {
		svc = svc[:idx]
	}
	if svc == "" {
		return "", false
	}
	return svc, true
}

// iamAction formats a service and method as an IAM action string.
func iamAction(service, method string) string {
	return service + ":" + method
}

// extractPackageName returns the last element of a dotted package path.
// e.g. "github.com/aws/aws-sdk-go-v2/service/s3" -> "s3".
func extractPackageName(importPath string) string {
	parts := strings.Split(importPath, "/")
	return parts[len(parts)-1]
}

// containsString checks if a slice contains the given string.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// AnalyzeGoSDKCalls walks dir recursively, parses .go files (skipping _test.go
// and vendor/), detects AWS SDK v2 client instantiation and method calls, and
// returns deduplicated AWSActions and all SDKUsages.
func AnalyzeGoSDKCalls(dir string) ([]AWSAction, []SDKUsage, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("analyze sdk calls: %w", err)
	}
	if !stat.IsDir() {
		return nil, nil, fmt.Errorf("analyze sdk calls: %q is not a directory", dir)
	}

	var usages []SDKUsage
	fset := token.NewFileSet()

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return nil
		}

		svcImportMap := make(map[string]string)
		for _, imp := range f.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)
			if svc, ok := isAWSSDKImport(impPath); ok {
				pkgName := extractPackageName(impPath)
				if imp.Name != nil {
					pkgName = imp.Name.Name
				}
				svcImportMap[pkgName] = svc
			}
		}
		if len(svcImportMap) == 0 {
			return nil
		}

		fullFile, parseErr := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if parseErr != nil {
			return nil
		}

		clientVars := make(map[string]string)
		ast.Inspect(fullFile, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}

			ident, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}

			callExpr, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := callExpr.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			selIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}

			methodName := sel.Sel.Name
			if methodName != "NewFromConfig" {
				return true
			}

			if svc, found := svcImportMap[selIdent.Name]; found {
				clientVars[ident.Name] = svc
			}
			return true
		})

		if len(clientVars) == 0 {
			return nil
		}

		ast.Inspect(fullFile, func(n ast.Node) bool {
			callExpr, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := callExpr.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			clientIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}

			svc, found := clientVars[clientIdent.Name]
			if !found {
				return true
			}

			method := sel.Sel.Name
			action := iamAction(svc, method)

			pos := fset.Position(callExpr.Pos())
			importPath := "github.com/aws/aws-sdk-go-v2/service/" + svc

			usages = append(usages, SDKUsage{
				FilePath:      path,
				LineNumber:    pos.Line,
				ServiceImport: importPath,
				Service:       svc,
				Method:        method,
				IAMAction:     action,
			})
			return true
		})

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("analyze sdk calls: %w", err)
	}

	actions := deduplicateActions(usages)
	return actions, usages, nil
}

// AnalyzeSDKCalls walks dir recursively and analyzes AWS SDK calls across Go, Python, and JavaScript/TypeScript files.
func AnalyzeSDKCalls(dir string) ([]AWSAction, []SDKUsage, error) {
	stat, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("analyze sdk calls: %w", err)
	}
	if !stat.IsDir() {
		return nil, nil, fmt.Errorf("analyze sdk calls: %q is not a directory", dir)
	}

	var allUsages []SDKUsage

	// 1. Go SDK calls
	_, goUsages, _ := AnalyzeGoSDKCalls(dir)
	allUsages = append(allUsages, goUsages...)

	// 2. Python (boto3) SDK calls
	pyUsages := AnalyzePythonSDKCalls(dir)
	allUsages = append(allUsages, pyUsages...)

	// 3. JavaScript / TypeScript (@aws-sdk) SDK calls
	jstsUsages := AnalyzeJSTSSDKCalls(dir)
	allUsages = append(allUsages, jstsUsages...)

	actions := deduplicateActions(allUsages)
	return actions, allUsages, nil
}

// Regexes for Python boto3 detection
var (
	rePyBotoClient   = regexp.MustCompile(`(\w+)\s*=\s*boto3\.(?:client|resource)\s*\(\s*['"](\w+)['"]`)
	rePyBotoMethod   = regexp.MustCompile(`(\w+)\.([a-z0-9_]+)\s*\(`)
)

// AnalyzePythonSDKCalls parses Python files for boto3 client instantiation and method calls.
func AnalyzePythonSDKCalls(dir string) []SDKUsage {
	var usages []SDKUsage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		baseName := d.Name()
		if !strings.HasSuffix(baseName, ".py") || strings.HasSuffix(baseName, "_test.py") || strings.HasPrefix(baseName, "test_") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		clientVars := make(map[string]string)
		scanner := bufio.NewScanner(file)
		lineNum := 0

		type pendingCall struct {
			varName string
			method  string
			line    int
		}
		var calls []pendingCall

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Detect client instantiation: s3 = boto3.client('s3')
			if matches := rePyBotoClient.FindAllStringSubmatch(line, -1); len(matches) > 0 {
				for _, m := range matches {
					if len(m) > 2 {
						clientVars[m[1]] = strings.ToLower(m[2])
					}
				}
			}

			// Detect method calls: s3.get_object(...)
			if matches := rePyBotoMethod.FindAllStringSubmatch(line, -1); len(matches) > 0 {
				for _, m := range matches {
					if len(m) > 2 {
						varName := m[1]
						methodName := m[2]
						if methodName != "client" && methodName != "resource" {
							calls = append(calls, pendingCall{varName: varName, method: methodName, line: lineNum})
						}
					}
				}
			}
		}

		for _, c := range calls {
			if svc, found := clientVars[c.varName]; found {
				pascalMethod := snakeToPascal(c.method)
				action := iamAction(svc, pascalMethod)
				usages = append(usages, SDKUsage{
					FilePath:      path,
					LineNumber:    c.line,
					ServiceImport: "boto3." + svc,
					Service:       svc,
					Method:        pascalMethod,
					IAMAction:     action,
				})
			}
		}

		return nil
	})
	return usages
}

var (
	reJSBotoClient   = regexp.MustCompile(`(?:new\s+(\w+)Client|require\s*\(\s*['"]@aws-sdk/client-(\w+)['"]\s*\)|from\s+['"]@aws-sdk/client-(\w+)['"])`)
	reJSCommandCall  = regexp.MustCompile(`new\s+(\w+)(?:Command)\s*\(`)
	reJSDirectMethod = regexp.MustCompile(`(\w+)\.([a-zA-Z0-9_]+)\s*\(`)
)

var ignoredDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true, ".venv": true, "venv": true, "dist": true, "build": true,
}

// AnalyzeJSTSSDKCalls parses JS/TS files for AWS SDK v2/v3 client usage.
func AnalyzeJSTSSDKCalls(dir string) []SDKUsage {
	var usages []SDKUsage
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		baseName := d.Name()
		if !isJSTSFile(baseName) || isTestJSTS(baseName) {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		servicesFound := make(map[string]bool)
		scanner := bufio.NewScanner(file)
		lineNum := 0

		type pendingCall struct {
			cmdOrMethod string
			line        int
		}
		var calls []pendingCall

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			if matches := reJSBotoClient.FindAllStringSubmatch(line, -1); len(matches) > 0 {
				for _, m := range matches {
					for i := 1; i < len(m); i++ {
						if m[i] != "" {
							svc := strings.ToLower(strings.TrimSuffix(m[i], "Client"))
							servicesFound[svc] = true
						}
					}
				}
			}

			if matches := reJSCommandCall.FindAllStringSubmatch(line, -1); len(matches) > 0 {
				for _, m := range matches {
					if len(m) > 1 {
						calls = append(calls, pendingCall{cmdOrMethod: m[1], line: lineNum})
					}
				}
			}
		}

		if len(servicesFound) == 0 {
			return nil
		}

		// Pick primary service if found
		var primarySvc string
		for s := range servicesFound {
			primarySvc = s
			break
		}

		for _, c := range calls {
			action := iamAction(primarySvc, c.cmdOrMethod)
			usages = append(usages, SDKUsage{
				FilePath:      path,
				LineNumber:    c.line,
				ServiceImport: "@aws-sdk/client-" + primarySvc,
				Service:       primarySvc,
				Method:        c.cmdOrMethod,
				IAMAction:     action,
			})
		}

		return nil
	})
	return usages
}

func isJSTSFile(name string) bool {
	exts := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	for _, e := range exts {
		if strings.HasSuffix(name, e) {
			return true
		}
	}
	return false
}

func isTestJSTS(name string) bool {
	return strings.Contains(name, ".test.") || strings.Contains(name, ".spec.") || strings.HasSuffix(name, "_test.ts")
}

func snakeToPascal(s string) string {
	parts := strings.Split(s, "_")
	for i := range parts {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// deduplicateActions collapses SDKUsage entries into deduplicated AWSActions
// with call-site counts.
func deduplicateActions(usages []SDKUsage) []AWSAction {
	seen := make(map[string]int)
	order := make([]string, 0, len(usages))

	for _, u := range usages {
		if _, ok := seen[u.IAMAction]; !ok {
			order = append(order, u.IAMAction)
		}
		seen[u.IAMAction]++
	}

	actions := make([]AWSAction, 0, len(order))
	for _, action := range order {
		parts := strings.SplitN(action, ":", 2)
		svc := parts[0]
		actions = append(actions, AWSAction{
			Service: svc,
			Action:  action,
			Count:   seen[action],
		})
	}
	return actions
}

