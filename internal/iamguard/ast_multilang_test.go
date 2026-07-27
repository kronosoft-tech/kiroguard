package iamguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeSDKCalls_MultiLang(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create Python file with boto3 calls
	pyFile := filepath.Join(tempDir, "app.py")
	pyContent := `import boto3

s3 = boto3.client('s3')
s3.get_object(Bucket='mybucket', Key='file.txt')

dynamo = boto3.client('dynamodb')
dynamo.put_item(TableName='users', Item={})
`
	if err := os.WriteFile(pyFile, []byte(pyContent), 0644); err != nil {
		t.Fatalf("failed to write python file: %v", err)
	}

	// 2. Create TS file with @aws-sdk calls
	tsFile := filepath.Join(tempDir, "service.ts")
	tsContent := `import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';

const client = new S3Client({});
client.send(new GetObjectCommand({ Bucket: 'mybucket' }));
`
	if err := os.WriteFile(tsFile, []byte(tsContent), 0644); err != nil {
		t.Fatalf("failed to write ts file: %v", err)
	}

	actions, usages, err := AnalyzeSDKCalls(tempDir)
	if err != nil {
		t.Fatalf("AnalyzeSDKCalls failed: %v", err)
	}

	if len(usages) == 0 {
		t.Fatalf("expected SDK usages for Python and TS, got 0")
	}

	foundPyS3 := false
	foundPyDynamo := false
	foundTSS3 := false

	for _, u := range usages {
		if u.IAMAction == "s3:GetObject" && u.ServiceImport == "boto3.s3" {
			foundPyS3 = true
		}
		if u.IAMAction == "dynamodb:PutItem" && u.ServiceImport == "boto3.dynamodb" {
			foundPyDynamo = true
		}
		if u.IAMAction == "s3:GetObjectCommand" || u.IAMAction == "s3:GetObject" {
			foundTSS3 = true
		}
	}

	if !foundPyS3 {
		t.Errorf("expected Python boto3 s3:GetObject usage")
	}
	if !foundPyDynamo {
		t.Errorf("expected Python boto3 dynamodb:PutItem usage")
	}
	if !foundTSS3 {
		t.Errorf("expected TS @aws-sdk s3 usage")
	}

	if len(actions) == 0 {
		t.Errorf("expected deduplicated AWS actions, got 0")
	}
}
