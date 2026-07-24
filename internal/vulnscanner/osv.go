package vulnscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/luiferdev/kiroguard/internal/logging"
)

const (
	defaultOSVBaseURL = "https://api.osv.dev"
	osvBatchTimeout   = 30 * time.Second
	// hydrateConcurrency bounds the concurrent /v1/vulns/{id} detail fetches so a
	// vulnerable manifest with many CVEs does not open an unbounded fan-out.
	hydrateConcurrency = 10
	// Retry policy for transient OSV failures (429 / 5xx / network).
	defaultOSVMaxAttempts = 3
	// Production backoff; the test constructor uses a tiny value to stay fast.
	defaultOSVBaseBackoff = 500 * time.Millisecond
	testOSVBaseBackoff    = time.Millisecond
)

// OSVClient queries the OSV.dev vulnerability database.
type OSVClient struct {
	httpClient  *http.Client
	baseURL     string
	maxAttempts int
	baseBackoff time.Duration
	logger      *slog.Logger
}

// OSVVulnerability represents a single vulnerability from OSV.dev.
type OSVVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details,omitempty"`
	Severity []OSVSeverity `json:"severity,omitempty"`
	Affected []OSVAffected `json:"affected,omitempty"`
}

// OSVSeverity represents the severity of a vulnerability.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVAffected represents the affected package info for a vulnerability.
type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges,omitempty"`
}

// OSVPackage identifies a package in the OSV ecosystem.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// OSVRange represents a version range affected by a vulnerability.
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events,omitempty"`
}

// OSVEvent represents an event in a version range (introduced or fixed).
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// OSV API request/response types

type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvQueryPackage `json:"package"`
	Version string          `json:"version"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []OSVVulnerability `json:"vulns,omitempty"`
}

// NewOSVClient creates an OSVClient with the default OSV.dev base URL.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient:  &http.Client{},
		baseURL:     defaultOSVBaseURL,
		maxAttempts: defaultOSVMaxAttempts,
		baseBackoff: defaultOSVBaseBackoff,
		logger:      logging.ModuleLogger("vuln-scanner"),
	}
}

// NewOSVClientWithURL creates an OSVClient with a custom base URL (for testing).
// It uses a tiny retry backoff so tests exercising the retry path stay fast.
func NewOSVClientWithURL(baseURL string) *OSVClient {
	return &OSVClient{
		httpClient:  &http.Client{},
		baseURL:     baseURL,
		maxAttempts: defaultOSVMaxAttempts,
		baseBackoff: testOSVBaseBackoff,
		logger:      logging.ModuleLogger("vuln-scanner"),
	}
}

// doRequest performs an HTTP request with bounded retries on transient failures
// (network errors, HTTP 429, and 5xx). Non-retryable statuses and context
// cancellation are terminal. The body (if any) is resent on each attempt.
func (c *OSVClient) doRequest(ctx context.Context, method, url string, body []byte) (*http.Response, error) {
	attempts := c.maxAttempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := c.backoff(ctx, attempt); err != nil {
				return nil, err
			}
		}

		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return nil, fmt.Errorf("osv: failed to create request: %w", err)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, err // terminal: caller's deadline/cancellation
			}
			c.logger.Warn("osv_retry", "event", "osv_retry", "attempt", attempt+1, "error", err.Error())
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("osv: API returned status %d", resp.StatusCode)
			resp.Body.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			c.logger.Warn("osv_retry", "event", "osv_retry", "attempt", attempt+1, "status", resp.StatusCode)
			continue
		}

		return resp, nil
	}
	return nil, lastErr
}

// backoff sleeps for an exponentially increasing delay with jitter, aborting
// early if the context is done.
func (c *OSVClient) backoff(ctx context.Context, attempt int) error {
	base := c.baseBackoff
	if base <= 0 {
		base = defaultOSVBaseBackoff
	}
	delay := base * time.Duration(int64(1)<<(attempt-1))
	jitter := time.Duration(rand.Int63n(int64(base) + 1))
	timer := time.NewTimer(delay + jitter)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueryBatch queries OSV.dev for vulnerabilities affecting the given dependencies.
// It enforces a 30-second total timeout for the batch request.
// Returns a map from dependency name to its vulnerabilities.
func (c *OSVClient) QueryBatch(ctx context.Context, deps []Dependency) (map[string][]OSVVulnerability, error) {
	if len(deps) == 0 {
		return make(map[string][]OSVVulnerability), nil
	}

	// Enforce 30-second timeout for the entire batch
	ctx, cancel := context.WithTimeout(ctx, osvBatchTimeout)
	defer cancel()

	// Build the batch request
	queries := make([]osvQuery, len(deps))
	for i, dep := range deps {
		queries[i] = osvQuery{
			Package: osvQueryPackage{
				Name:      dep.Name,
				Ecosystem: dep.Ecosystem,
			},
			Version: dep.Version,
		}
	}

	reqBody := osvQueryBatchRequest{Queries: queries}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("osv: failed to marshal request: %w", err)
	}

	// Execute request with retry on transient failures.
	url := c.baseURL + "/v1/querybatch"
	resp, err := c.doRequest(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: API returned status %d", resp.StatusCode)
	}

	// Decode response
	var batchResp osvQueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("osv: failed to decode response: %w", err)
	}

	// Map results back to dependency names
	results := make(map[string][]OSVVulnerability)
	for i, result := range batchResp.Results {
		if i >= len(deps) {
			break
		}
		if len(result.Vulns) > 0 {
			results[deps[i].Name] = result.Vulns
		}
	}

	// The batch endpoint returns MINIMAL vulnerabilities (id + modified only).
	// Hydrate each one with full detail (severity, ranges, fixed) via /v1/vulns/{id}.
	c.hydrate(ctx, results)

	return results, nil
}

// hydrate fills in full vulnerability detail for any minimal vuln (one that has
// an ID but no severity and no affected ranges) by fetching /v1/vulns/{id}.
// Fetches run concurrently, bounded by hydrateConcurrency, writing into distinct
// slice elements (no shared-element races). A failed fetch leaves the minimal
// vuln in place so the CVE id is still reported.
func (c *OSVClient) hydrate(ctx context.Context, results map[string][]OSVVulnerability) {
	type target struct {
		pkg string
		idx int
		id  string
	}
	var targets []target
	for pkg, vulns := range results {
		for i := range vulns {
			if vulns[i].ID != "" && len(vulns[i].Severity) == 0 && len(vulns[i].Affected) == 0 {
				targets = append(targets, target{pkg: pkg, idx: i, id: vulns[i].ID})
			}
		}
	}
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, hydrateConcurrency)
	var wg sync.WaitGroup
	for _, tg := range targets {
		wg.Add(1)
		go func(tg target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			full, err := c.GetVuln(ctx, tg.id)
			if err != nil || full == nil {
				// Keep the minimal vuln (the id is still reported) but leave a trace.
				c.logger.Warn("hydration_failed",
					"event", "hydration_failed", "vuln_id", tg.id, "error", errString(err))
				return
			}
			results[tg.pkg][tg.idx] = *full
		}(tg)
	}
	wg.Wait()
}

// GetVuln fetches full detail for a single vulnerability by id from /v1/vulns/{id},
// retrying transient failures.
func (c *OSVClient) GetVuln(ctx context.Context, id string) (*OSVVulnerability, error) {
	url := c.baseURL + "/v1/vulns/" + id
	resp, err := c.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: vuln API returned status %d", resp.StatusCode)
	}

	var v OSVVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("osv: failed to decode vuln: %w", err)
	}
	return &v, nil
}

// errString safely renders an error for structured logging (handles nil).
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
