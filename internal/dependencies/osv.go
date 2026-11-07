// Package dependencies provides explicit opt-in vulnerability lookup.
package dependencies

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
	"io"
	"net/http"
	"regexp"
	"time"
)

var vulnerabilityID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var exact = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9.-]+)?$`)

type Client struct {
	HTTP     *http.Client
	Endpoint string
}

func DefaultClient() Client {
	return Client{HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("OSV redirects forbidden") }}, Endpoint: "https://api.osv.dev/v1/querybatch"}
}
func (c Client) Check(ctx context.Context, r *f.Report) (resultErr error) {
	m := r.Module("osv")
	m.Required = true
	m.Status = "completed"
	defer func() {
		if resultErr != nil {
			r.Issue("osv", "failed", "lookup_failed", "", "Vulnerability lookup failed; no clean verdict is available")
		}
		r.Normalize()
	}()
	queries := []any{}
	components := []f.Component{}
	seen := map[string]bool{}
	for _, dep := range r.Components {
		if !exact.MatchString(dep.Version) {
			continue
		}
		key := dep.Ecosystem + "\x00" + dep.Name + "\x00" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		queries = append(queries, map[string]any{"version": dep.Version, "package": map[string]string{"name": dep.Name, "ecosystem": dep.Ecosystem}})
		components = append(components, dep)
	}
	if len(queries) > 1000 {
		return fmt.Errorf("OSV query limit of 1000 packages exceeded")
	}
	r.Module("osv").Inputs = len(queries)
	if len(queries) == 0 {
		r.Issue("osv", "partial", "no_exact_versions", "", "No exact supported dependency versions available")
		r.Coverage = append(r.Coverage, "OSV: no exact supported package versions available")
		return nil
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("OSV returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 8<<20 {
		return fmt.Errorf("OSV response exceeds size limit")
	}
	var payload struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			Next string `json:"next_page_token"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("invalid OSV JSON: %w", err)
	}
	if len(payload.Results) != len(components) {
		return fmt.Errorf("OSV result count mismatch")
	}
	for _, result := range payload.Results {
		if result.Next != "" {
			return fmt.Errorf("OSV results require pagination; coverage incomplete")
		}
		for _, v := range result.Vulns {
			if len(v.ID) > 150 || !vulnerabilityID.MatchString(v.ID) {
				return fmt.Errorf("invalid OSV vulnerability identifier")
			}
		}
	}
	vulnerabilityCount := 0
	r.Module("osv").Analyzed = len(components)
	for i, result := range payload.Results {
		dep := components[i]
		for _, v := range result.Vulns {
			vulnerabilityCount++
			r.Findings = append(r.Findings, f.Finding{ID: "OSV-" + v.ID + "-" + dep.Name + "-" + dep.Version, RuleID: "RS300", Severity: "MEDIUM", Confidence: "high", Category: "vulnerability", Description: v.ID + " affects " + dep.Name + "@" + dep.Version, Evidence: []f.Evidence{{File: "dependency-inventory", Line: 1, Description: "OSV package/version match; installation and reachability not established"}}, Impact: "Known vulnerability; not evidence of a malicious package. Severity is a triage default, not upstream CVSS.", Remediation: "Review https://osv.dev/vulnerability/" + v.ID + " and upgrade to a fixed version", Source: "osv.dev"})
		}
	}
	limits := r.Limitations[:0]
	for _, limit := range r.Limitations {
		if limit != "No vulnerability database queried; absence of findings is not a clean bill of health" {
			limits = append(limits, limit)
		}
	}
	r.Limitations = limits
	r.Coverage = append(r.Coverage, fmt.Sprintf("OSV queried %d exact package versions; unresolved ranges skipped", len(queries)))
	if vulnerabilityCount > 0 && r.Risk < 40 {
		r.Risk = 40
	}
	return nil
}
