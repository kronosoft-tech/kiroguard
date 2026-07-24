package lambdaguard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

var supportedIaCExtensions = map[string]string{
	".yaml": "yaml",
	".yml":  "yaml",
	".tf":   "terraform",
	".json": "json",
	".ts":   "cdk",
	".js":   "cdk",
}

var excludedDirs = map[string]bool{
	"vendor":     true,
	"node_modules": true,
	".git":       true,
	".terraform": true,
	"cdk.out":    true,
}

var (
	samFunctionRE       = regexp.MustCompile(`Type:\s*AWS::Serverless::Function`)
	serverlessFuncRE    = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*:`)
	terraformResourceRE = regexp.MustCompile(`resource\s+"aws_lambda_function"\s+"([^"]+)"`)
)

const defaultIaCMaxFileSize int64 = 5 * 1024 * 1024

func ParseLambdaConfigs(ctx context.Context, dir string, maxFileSizeMB int) ([]LambdaConfig, error) {
	var configs []LambdaConfig

	maxSize := int64(maxFileSizeMB) * 1024 * 1024
	if maxSize <= 0 {
		maxSize = defaultIaCMaxFileSize
	}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			if excludedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if _, ok := supportedIaCExtensions[ext]; !ok {
			if !isKnownIaCName(path) {
				return nil
			}
			ext = filepath.Ext(path)
		}

		info, statErr := d.Info()
		if statErr != nil {
			return nil
		}

		if info.Size() > maxSize {
			slog.Warn("file exceeds max size, skipping", "path", path, "size_mb", info.Size()/(1024*1024))
			return nil
		}

		parsed, parseErr := parseFile(path)
		if parseErr != nil {
			slog.Warn("failed to parse IaC file", "path", path, "error", parseErr)
			return nil
		}
		configs = append(configs, parsed...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk dir %s: %w", dir, err)
	}
	return configs, nil
}

func isKnownIaCName(path string) bool {
	name := filepath.Base(path)
	known := []string{
		"template.yaml", "template.yml",
		"serverless.yaml", "serverless.yml",
	}
	for _, k := range known {
		if name == k {
			return true
		}
	}
	return false
}

func parseFile(path string) ([]LambdaConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", path, err)
	}

	name := filepath.Base(path)
	ext := filepath.Ext(path)

	switch {
	case name == "template.yaml" || name == "template.yml":
		return parseSAM(path, data)
	case name == "serverless.yaml" || name == "serverless.yml":
		return parseServerless(path, data)
	case ext == ".tf":
		return parseTerraform(path, data)
	case ext == ".ts" || ext == ".js":
		return parseCDK(path, data)
	case ext == ".json":
		return parseSAM(path, data)
	default:
		return nil, nil
	}
}

func parseSAM(path string, data []byte) ([]LambdaConfig, error) {
	var doc struct {
		Resources map[string]struct {
			Type       string `yaml:"Type"`
			Properties *struct {
				FunctionName        string            `yaml:"FunctionName"`
				Runtime             string            `yaml:"Runtime"`
				Timeout             int               `yaml:"Timeout"`
				MemorySize          int               `yaml:"MemorySize"`
				RoleARN             string            `yaml:"Role"`
				RoleStatements      []IAMStatement    `yaml:"Policies"`
				Environment         map[string]string `yaml:"Environment"`
				DLQTarget           string            `yaml:"DeadLetterQueue"`
				VPCConfig           *VPCConfig        `yaml:"VpcConfig"`
				ReservedConcurrency int               `yaml:"ReservedConcurrentExecutions"`
				TracingMode         string            `yaml:"Tracing"`
				Architectures       []string          `yaml:"Architectures"`
				Handler             string            `yaml:"Handler"`
				Description         string            `yaml:"Description"`
			} `yaml:"Properties"`
		} `yaml:"Resources"`
	}

	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SAM YAML: %w", err)
	}

	var configs []LambdaConfig
	for name, res := range doc.Resources {
		if res.Type != "AWS::Serverless::Function" || res.Properties == nil {
			continue
		}
		props := res.Properties

		envVars := props.Environment
		if envVars == nil {
			envVars = map[string]string{}
		}

		cfg := LambdaConfig{
			FunctionName:        props.FunctionName,
			SourceFile:          path,
			Runtime:             props.Runtime,
			Timeout:             props.Timeout,
			MemorySize:          props.MemorySize,
			RoleARN:             props.RoleARN,
			RoleStatements:      props.RoleStatements,
			Environment:         envVars,
			DLQTarget:           props.DLQTarget,
			VPCConfig:           props.VPCConfig,
			ReservedConcurrency: props.ReservedConcurrency,
			TracingMode:         props.TracingMode,
			Architectures:       props.Architectures,
			Handler:             props.Handler,
			Description:         props.Description,
			IaCFormat:           "sam",
		}

		if cfg.FunctionName == "" {
			cfg.FunctionName = name
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

func parseServerless(path string, data []byte) ([]LambdaConfig, error) {
	var doc struct {
		Functions map[string]struct {
			Handler    string            `yaml:"handler"`
			Runtime    string            `yaml:"runtime"`
			Timeout    int               `yaml:"timeout"`
			MemorySize int               `yaml:"memorySize"`
			RoleARN    string            `yaml:"role"`
			RoleStatements []IAMStatement `yaml:"iamRoleStatements"`
			Environment   map[string]string `yaml:"environment"`
			Description   string            `yaml:"description"`
			Architectures []string          `yaml:"architectures"`
		} `yaml:"functions"`
	}

	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse Serverless YAML: %w", err)
	}

	var configs []LambdaConfig
	for name, fn := range doc.Functions {
		envVars := fn.Environment
		if envVars == nil {
			envVars = map[string]string{}
		}

		cfg := LambdaConfig{
			FunctionName:   name,
			SourceFile:     path,
			Runtime:        fn.Runtime,
			Timeout:        fn.Timeout,
			MemorySize:     fn.MemorySize,
			RoleARN:        fn.RoleARN,
			RoleStatements: fn.RoleStatements,
			Environment:    envVars,
			Handler:        fn.Handler,
			Description:    fn.Description,
			Architectures:  fn.Architectures,
			IaCFormat:      "serverless",
		}

		if cfg.ReservedConcurrency == 0 {
			cfg.ReservedConcurrency = -1
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}

func parseTerraform(path string, data []byte) ([]LambdaConfig, error) {
	content := string(data)
	matches := terraformResourceRE.FindAllStringSubmatch(content, -1)

	var configs []LambdaConfig
	for _, m := range matches {
		funcName := m[1]

		cfg := LambdaConfig{
			FunctionName:        funcName,
			SourceFile:          path,
			IaCFormat:           "terraform",
			ReservedConcurrency: -1,
			Environment:         map[string]string{},
		}

		cfg.Timeout = extractIntAttr(content, funcName, "timeout")
		cfg.MemorySize = extractIntAttr(content, funcName, "memory_size")
		cfg.Runtime = extractStrAttr(content, funcName, "runtime")
		cfg.Handler = extractStrAttr(content, funcName, "handler")
		cfg.Description = extractStrAttr(content, funcName, "description")
		cfg.RoleARN = extractStrAttr(content, funcName, "role")
		cfg.TracingMode = extractStrAttr(content, funcName, "tracing_config")

		if cfg.Timeout == 0 {
			cfg.Timeout = 3
		}
		if cfg.MemorySize == 0 {
			cfg.MemorySize = 128
		}

		configs = append(configs, cfg)
	}
	return configs, nil
}

func extractIntAttr(content, funcName, attr string) int {
	re := regexp.MustCompile(regexp.QuoteMeta(funcName) + `"\s*\{[^}]*` + attr + `\s*=\s*(\d+)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		var val int
		fmt.Sscanf(matches[1], "%d", &val)
		return val
	}
	return 0
}

func extractStrAttr(content, funcName, attr string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(funcName) + `"\s*\{[^}]*` + attr + `\s*=\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func parseCDK(path string, data []byte) ([]LambdaConfig, error) {
	content := string(data)

	newLambdaRE := regexp.MustCompile(`new\s+(?:lambda\.)?Function\(`)
	if !newLambdaRE.MatchString(content) {
		return nil, nil
	}

	handlerRE := regexp.MustCompile(`handler:\s*["']([^"']+)["']`)
	runtimeRE := regexp.MustCompile(`runtime:\s*(?:Runtime\.|lambda\.)?([a-zA-Z0-9_]+)`)

	handlerMatches := handlerRE.FindAllStringSubmatch(content, -1)
	if len(handlerMatches) == 0 {
		cfg := LambdaConfig{
			FunctionName: filepath.Base(path),
			SourceFile:   path,
			IaCFormat:    "cdk",
			Environment:  map[string]string{},
		}
		cfg.ReservedConcurrency = -1
		return []LambdaConfig{cfg}, nil
	}

	var configs []LambdaConfig
	for _, hm := range handlerMatches {
		cfg := LambdaConfig{
			FunctionName: filepath.Base(path),
			SourceFile:   path,
			Handler:      hm[1],
			IaCFormat:    "cdk",
			Environment:  map[string]string{},
		}
		cfg.ReservedConcurrency = -1

		runtimeMatches := runtimeRE.FindStringSubmatch(content)
		if len(runtimeMatches) > 1 {
			cfg.Runtime = runtimeMatches[1]
		}
		configs = append(configs, cfg)
	}
	return configs, nil
}
