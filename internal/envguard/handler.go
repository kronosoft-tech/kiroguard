package envguard

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/luiferdev/kiroguard/internal/rpc"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// EnvGuardHandler wires together the secret scanner, ignore filter, and migrator
// to provide the complete Env-Guard MCP tool.
type EnvGuardHandler struct {
	scanner     *SecretScanner
	ignore      *IgnoreParser // may be nil if no ignore file
	migrator    *Migrator     // may be nil if AWS not configured
	workerCount int           // max concurrent migration goroutines
	limiter     *rate.Limiter // shared rate limiter for AWS API calls
}

// EnvGuardInput represents the input parameters for the envguard/scan tool.
type EnvGuardInput struct {
	Diff     string `json:"diff"`
	FilePath string `json:"file_path,omitempty"`
}

// EnvGuardOutput represents the output of the envguard/scan tool.
type EnvGuardOutput struct {
	Blocked  bool            `json:"blocked"`
	Findings []SecretFinding `json:"findings"`
	Message  string          `json:"message"`
}

// NewEnvGuardHandler creates a new EnvGuardHandler with the given components.
// ignore and migrator may be nil if not available.
func NewEnvGuardHandler(scanner *SecretScanner, ignore *IgnoreParser, migrator *Migrator, workerCount int, limiter *rate.Limiter) *EnvGuardHandler {
	return &EnvGuardHandler{
		scanner:     scanner,
		ignore:      ignore,
		migrator:    migrator,
		workerCount: workerCount,
		limiter:     limiter,
	}
}

// sanitizeEnvName converts a secret type and file path into a safe environment variable name.
// Example: "aws_access_key" from "src/config.go" → "KIROGUARD_AWS_ACCESS_KEY"
var nonAlphanumRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func sanitizeEnvName(secretType string) string {
	name := nonAlphanumRegex.ReplaceAllString(secretType, "_")
	name = strings.Trim(name, "_")
	return "KIROGUARD_" + strings.ToUpper(name)
}

// generateReplacement produces a replacement snippet for a secret finding.
// If the finding has a migrated ARN, it references the ARN directly.
// Otherwise, it uses an environment variable reference.
// The replacement MUST NOT contain the original secret value.
func generateReplacement(finding SecretFinding) string {
	if finding.MigratedARN != "" {
		return fmt.Sprintf(`os.Getenv("%s")`, sanitizeEnvName(finding.SecretType))
	}
	return fmt.Sprintf(`os.Getenv("%s")`, sanitizeEnvName(finding.SecretType))
}

// Handle processes an envguard/scan request.
// Flow:
//  1. Parse params as EnvGuardInput
//  2. Call scanner.Scan to get findings
//  3. If ignore is not nil, filter findings
//  4. If findings remain, set blocked = true
//  5. For each finding with migrator available, attempt migration
//  6. Generate replacement snippets
//  7. Return EnvGuardOutput
func (h *EnvGuardHandler) Handle(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var input EnvGuardInput
	if err := json.Unmarshal(params, &input); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	if input.Diff == "" {
		return &EnvGuardOutput{
			Blocked:  false,
			Findings: []SecretFinding{},
			Message:  "No diff provided",
		}, nil
	}

	// Step 1: Scan the diff for secrets
	findings := h.scanner.Scan(input.Diff)

	// Step 2: Apply ignore filter if available
	if h.ignore != nil && len(findings) > 0 {
		findings = h.ignore.Filter(findings)
	}

	// Step 3: If no findings after filtering, return clean result
	if len(findings) == 0 {
		return &EnvGuardOutput{
			Blocked:  false,
			Findings: []SecretFinding{},
			Message:  "No secrets detected",
		}, nil
	}

	// Step 4: Migrate findings concurrently (if migrator available)
	if h.migrator != nil {
		h.migrateAll(ctx, findings)
	}

	// Step 5: Generate replacements and clear secret values (sequential, post-migration)
	for i := range findings {
		findings[i].Replacement = generateReplacement(findings[i])
		findings[i].SecretValue = ""
	}

	// Step 6: Build message
	message := fmt.Sprintf("Blocked: %d secret(s) detected", len(findings))
	if h.migrator == nil {
		message += " (automatic migration unavailable - AWS not configured)"
	}

	return &EnvGuardOutput{
		Blocked:  true,
		Findings: findings,
		Message:  message,
	}, nil
}

// migrateAll executes all migrations concurrently using a bounded worker pool.
// Each finding is processed independently; errors are recorded per-finding.
// The method blocks until all goroutines complete.
func (h *EnvGuardHandler) migrateAll(ctx context.Context, findings []SecretFinding) {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(h.workerCount)

	for i := range findings {
		i := i // capture loop variable
		g.Go(func() error {
			// Rate limit before calling AWS
			if err := h.limiter.Wait(gCtx); err != nil {
				findings[i].MigrationErr = err.Error()
				return nil // don't cancel others
			}

			arn, err := h.migrator.Migrate(gCtx, findings[i])
			if err != nil {
				findings[i].MigrationErr = err.Error()
			} else {
				findings[i].MigratedARN = arn
			}
			return nil // never return error — independent error handling
		})
	}

	g.Wait()
}

// RegisterEnvGuard registers the envguard/scan tool handler with the RPC dispatcher.
func RegisterEnvGuard(d *rpc.Dispatcher, handler *EnvGuardHandler) {
	d.Register("envguard/scan", handler.Handle)
}
