package vulnscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	defaultOSVBaseURL = "https://api.osv.dev"
	osvBatchTimeout   = 30 * time.Second
	// hydrateConcurrency bounds the concurrent /v1/vulns/{id} detail fetches so a
	// vulnerable manifest with many CVEs does not open an unbounded fan-out.
	hydrateConcurrency = 10
)

// OSVClient queries the OSV.dev vulnerability database.
type OSVClient struct {
	httpClient *http.Client
	baseURL    string
}

// OSVVulnerability represents a single vulnerability from OSV.dev.
type OSVVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
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
		httpClient: &http.Client{},
		baseURL:    defaultOSVBaseURL,
	}
}

// NewOSVClientWithURL creates an OSVClient with a custom base URL (for testing).
func NewOSVClientWithURL(baseURL string) *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{},
		baseURL:    baseURL,
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

	// Create HTTP request
	url := c.baseURL + "/v1/querybatch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: request failed: %w", err)
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
				return // keep the minimal vuln; the id is still reported
			}
			results[tg.pkg][tg.idx] = *full
		}(tg)
	}
	wg.Wait()
}

// GetVuln fetches full detail for a single vulnerability by id from /v1/vulns/{id}.
func (c *OSVClient) GetVuln(ctx context.Context, id string) (*OSVVulnerability, error) {
	url := c.baseURL + "/v1/vulns/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("osv: failed to create vuln request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: vuln request failed: %w", err)
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
