package envguard

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// MigratorConfig holds configuration for the secret migrator.
type MigratorConfig struct {
	Target    string // "secrets_manager" or "ssm"
	SSMPrefix string // e.g., "/kiroguard/"
	Region    string
}

// SecretsManagerClient defines the interface for AWS Secrets Manager operations.
type SecretsManagerClient interface {
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
}

// SSMClient defines the interface for AWS SSM Parameter Store operations.
type SSMClient interface {
	PutParameter(ctx context.Context, params *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// Migrator handles migrating detected secrets to AWS Secrets Manager or SSM Parameter Store.
type Migrator struct {
	smClient  SecretsManagerClient
	ssmClient SSMClient
	config    MigratorConfig
}

// nameRegexp matches characters that are not alphanumeric or hyphens.
var nameRegexp = regexp.MustCompile(`[^a-zA-Z0-9-]`)

// sanitizeName converts a file path and secret type into a safe name for AWS resources.
// It replaces special characters with hyphens and prefixes with "kiroguard-".
func sanitizeName(filePath, secretType string) string {
	combined := filePath + "-" + secretType
	sanitized := nameRegexp.ReplaceAllString(combined, "-")
	// Collapse multiple consecutive hyphens into one.
	for strings.Contains(sanitized, "--") {
		sanitized = strings.ReplaceAll(sanitized, "--", "-")
	}
	// Trim leading/trailing hyphens.
	sanitized = strings.Trim(sanitized, "-")
	return "kiroguard-" + sanitized
}

// NewMigrator creates a new Migrator with AWS clients based on the provided configuration.
func NewMigrator(ctx context.Context, cfg MigratorConfig) (*Migrator, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.Region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	m := &Migrator{config: cfg}

	switch cfg.Target {
	case "secrets_manager":
		m.smClient = secretsmanager.NewFromConfig(awsCfg)
	case "ssm":
		m.ssmClient = ssm.NewFromConfig(awsCfg)
	default:
		return nil, fmt.Errorf("unsupported migration target: %q (use \"secrets_manager\" or \"ssm\")", cfg.Target)
	}

	return m, nil
}

// NewMigratorWithClients creates a Migrator with pre-configured clients (useful for testing).
func NewMigratorWithClients(cfg MigratorConfig, smClient SecretsManagerClient, ssmClient SSMClient) *Migrator {
	return &Migrator{
		smClient:  smClient,
		ssmClient: ssmClient,
		config:    cfg,
	}
}

// Migrate stores the detected secret in AWS Secrets Manager or SSM Parameter Store
// and returns the ARN of the created resource. It enforces a 10-second timeout.
func (m *Migrator) Migrate(ctx context.Context, secret SecretFinding) (string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	name := sanitizeName(secret.FilePath, secret.SecretType)

	switch m.config.Target {
	case "secrets_manager":
		return m.migrateToSecretsManager(timeoutCtx, name, secret.SecretValue)
	case "ssm":
		return m.migrateToSSM(timeoutCtx, name, secret.SecretValue)
	default:
		return "", fmt.Errorf("unsupported migration target: %q", m.config.Target)
	}
}

func (m *Migrator) migrateToSecretsManager(ctx context.Context, name, value string) (string, error) {
	if m.smClient == nil {
		return "", fmt.Errorf("secrets manager client not initialized")
	}

	output, err := m.smClient.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(value),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create secret in Secrets Manager: %w", err)
	}

	if output.ARN == nil {
		return "", fmt.Errorf("secrets manager returned nil ARN")
	}

	return *output.ARN, nil
}

func (m *Migrator) migrateToSSM(ctx context.Context, name, value string) (string, error) {
	if m.ssmClient == nil {
		return "", fmt.Errorf("ssm client not initialized")
	}

	paramName := m.config.SSMPrefix + name

	output, err := m.ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:  aws.String(paramName),
		Value: aws.String(value),
		Type:  ssmtypes.ParameterTypeSecureString,
	})
	if err != nil {
		return "", fmt.Errorf("failed to put parameter in SSM: %w", err)
	}

	// SSM PutParameter doesn't return ARN directly; we construct it.
	// In a real implementation, we'd need the account ID and region.
	// For now, we use the Tier field presence to confirm success and return a constructed ARN.
	if output == nil {
		return "", fmt.Errorf("ssm returned nil output")
	}

	// Construct the ARN for the SSM parameter.
	// Format: arn:aws:ssm:<region>:<account-id>:parameter<name>
	// Since we don't have account ID readily available, we return a reference path.
	// The caller should use the parameter name as the reference.
	arn := fmt.Sprintf("arn:aws:ssm:%s::parameter%s", m.config.Region, paramName)
	return arn, nil
}
