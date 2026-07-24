package lambdaguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSAM_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.yaml")
	content := `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: my-func
      Runtime: nodejs20.x
      Timeout: 30
      MemorySize: 512
      Handler: index.handler
      Description: My Lambda
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	cfg := configs[0]
	if cfg.FunctionName != "my-func" {
		t.Errorf("FunctionName = %q, want %q", cfg.FunctionName, "my-func")
	}
	if cfg.Runtime != "nodejs20.x" {
		t.Errorf("Runtime = %q, want %q", cfg.Runtime, "nodejs20.x")
	}
	if cfg.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", cfg.Timeout)
	}
	if cfg.MemorySize != 512 {
		t.Errorf("MemorySize = %d, want 512", cfg.MemorySize)
	}
	if cfg.IaCFormat != "sam" {
		t.Errorf("IaCFormat = %q, want %q", cfg.IaCFormat, "sam")
	}
}

func TestParseSAM_NoFunctions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.yaml")
	content := `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0", len(configs))
	}
}

func TestParseServerless_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serverless.yml")
	content := `
service: my-service
functions:
  hello:
    handler: handler.hello
    runtime: python3.12
    timeout: 10
    memorySize: 256
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	cfg := configs[0]
	if cfg.FunctionName != "hello" {
		t.Errorf("FunctionName = %q, want %q", cfg.FunctionName, "hello")
	}
	if cfg.Runtime != "python3.12" {
		t.Errorf("Runtime = %q, want %q", cfg.Runtime, "python3.12")
	}
	if cfg.Timeout != 10 {
		t.Errorf("Timeout = %d, want 10", cfg.Timeout)
	}
	if cfg.MemorySize != 256 {
		t.Errorf("MemorySize = %d, want 256", cfg.MemorySize)
	}
	if cfg.IaCFormat != "serverless" {
		t.Errorf("IaCFormat = %q, want %q", cfg.IaCFormat, "serverless")
	}
}

func TestParseTerraform_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lambda.tf")
	content := `
resource "aws_lambda_function" "my_func" {
  function_name = "my-func"
  runtime       = "nodejs20.x"
  timeout       = 30
  memory_size   = 512
  handler       = "index.handler"
  description   = "Test function"
  role          = "arn:aws:iam::123456789012:role/lambda-role"
}
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	cfg := configs[0]
	if cfg.FunctionName != "my_func" {
		t.Errorf("FunctionName = %q, want %q", cfg.FunctionName, "my_func")
	}
	if cfg.Runtime != "nodejs20.x" {
		t.Errorf("Runtime = %q, want %q", cfg.Runtime, "nodejs20.x")
	}
	if cfg.Timeout != 30 {
		t.Errorf("Timeout = %d, want 30", cfg.Timeout)
	}
	if cfg.MemorySize != 512 {
		t.Errorf("MemorySize = %d, want 512", cfg.MemorySize)
	}
	if cfg.IaCFormat != "terraform" {
		t.Errorf("IaCFormat = %q, want %q", cfg.IaCFormat, "terraform")
	}
}

func TestParseCDK_TypeScript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stack.ts")
	content := `
import * as lambda from 'aws-cdk-lib/aws-lambda';

new lambda.Function(this, 'MyFunction', {
  runtime: lambda.Runtime.NODEJS_20_X,
  handler: 'index.handler',
  code: lambda.Code.fromAsset('lambda'),
});
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) == 0 {
		t.Fatal("expected at least 1 config from CDK file")
	}
	cfg := configs[0]
	if cfg.Handler != "index.handler" {
		t.Errorf("Handler = %q, want %q", cfg.Handler, "index.handler")
	}
	if cfg.IaCFormat != "cdk" {
		t.Errorf("IaCFormat = %q, want %q", cfg.IaCFormat, "cdk")
	}
}

func TestParseLambdaConfigs_MixedFiles(t *testing.T) {
	dir := t.TempDir()

	samPath := filepath.Join(dir, "template.yaml")
	os.WriteFile(samPath, []byte(`
Resources:
  Func1:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: func1
      Runtime: nodejs20.x
`), 0644)

	tfPath := filepath.Join(dir, "main.tf")
	os.WriteFile(tfPath, []byte(`
resource "aws_lambda_function" "func2" {
  function_name = "func2"
  runtime       = "python3.12"
}
`), 0644)

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 2 {
		t.Errorf("got %d configs, want 2", len(configs))
	}
}

func TestParseLambdaConfigs_NoIaCFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0644)

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0", len(configs))
	}
}

func TestParseLambdaConfigs_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0", len(configs))
	}
}

func TestParseLambdaConfigs_FileOver5MB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.yaml")

	data := make([]byte, 6*1024*1024)
	data[0] = 'R'
	data[1] = 'e'
	data[2] = 's'
	data[3] = 'o'
	data[4] = 'u'
	data[5] = 'r'
	data[6] = 'c'
	data[7] = 'e'

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0 (file should be skipped)", len(configs))
	}
}

func TestParseLambdaConfigs_NestedDirectories(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	os.MkdirAll(subdir, 0755)

	path := filepath.Join(subdir, "template.yaml")
	os.WriteFile(path, []byte(`
Resources:
  NestedFunc:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: nested-func
      Runtime: provided.al2023
`), 0644)

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 1 {
		t.Errorf("got %d configs, want 1", len(configs))
	}
}

func TestParseLambdaConfigs_SkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()

	for _, excluded := range []string{"node_modules", ".terraform"} {
		sub := filepath.Join(dir, excluded)
		os.MkdirAll(sub, 0755)
		os.WriteFile(filepath.Join(sub, "template.yaml"), []byte(`
Resources:
  BadFunc:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: should-be-skipped
      Runtime: nodejs20.x
`), 0644)
	}

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 0 {
		t.Errorf("got %d configs, want 0 (all in excluded dirs)", len(configs))
	}
}

func TestParseLambdaConfigs_SAMWithEnvVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "template.yaml")
	content := `
Resources:
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      Runtime: nodejs20.x
      Environment:
        DB_PASSWORD: supersecret
        DB_HOST: localhost
`
	os.WriteFile(path, []byte(content), 0644)

	configs, err := ParseLambdaConfigs(context.Background(), dir, 5)
	if err != nil {
		t.Fatalf("ParseLambdaConfigs error: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	if configs[0].Environment["DB_PASSWORD"] != "supersecret" {
		t.Errorf("DB_PASSWORD = %q", configs[0].Environment["DB_PASSWORD"])
	}
	if configs[0].Environment["DB_HOST"] != "localhost" {
		t.Errorf("DB_HOST = %q", configs[0].Environment["DB_HOST"])
	}
}
