package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type CoverageIssue struct {
	Code        string `json:"code"`
	File        string `json:"file,omitempty"`
	Description string `json:"description"`
}
type ModuleCoverage struct {
	Module      string          `json:"module"`
	Status      string          `json:"status"`
	Required    bool            `json:"required"`
	Inputs      int             `json:"inputs"`
	Analyzed    int             `json:"analyzed"`
	IssueCount  int             `json:"issue_count"`
	Issues      []CoverageIssue `json:"issues"`
	ToolVersion string          `json:"tool_version,omitempty"`
}
type Suppression struct {
	RuleID string `json:"rule_id"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func (r *Report) Module(name string) *ModuleCoverage {
	for i := range r.Modules {
		if r.Modules[i].Module == name {
			return &r.Modules[i]
		}
	}
	r.Modules = append(r.Modules, ModuleCoverage{Module: name, Status: "completed", Required: true, Issues: []CoverageIssue{}})
	return &r.Modules[len(r.Modules)-1]
}
func (r *Report) Issue(module, status, code, file, description string) {
	m := r.Module(module)
	m.IssueCount++
	priority := map[string]int{"completed": 0, "skipped": 1, "unsupported": 2, "partial": 3, "failed": 4}
	if priority[status] > priority[m.Status] {
		m.Status = status
	}
	if len(m.Issues) < 64 {
		m.Issues = append(m.Issues, CoverageIssue{code, file, description})
	}
	if m.Required && (status == "partial" || status == "unsupported" || status == "failed") {
		r.Complete = false
	}
}
func Hash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// Identify separates semantic identity from an occurrence's source position. Content
// is hashed, never stored, and must not be included in output descriptions.
func Identify(v *Finding, semantic string) {
	if v.Fingerprint == "" {
		v.Fingerprint = Hash(v.RuleID, v.Evidence[0].File, strings.Join(strings.Fields(semantic), " "))
	}
	if v.ID == "" {
		v.ID = "RS-" + Hash(v.Fingerprint, fmt.Sprint(v.Evidence[0].Line), fmt.Sprint(v.Evidence[0].Column))[:16]
	}
}
func (r *Report) Normalize() {
	for i := range r.Findings {
		v := &r.Findings[i]
		if len(v.Evidence) > 0 {
			Identify(v, v.Description)
			for j := range v.Evidence {
				e := &v.Evidence[j]
				if e.EndLine == 0 {
					e.EndLine = e.Line
				}
				if e.Column == 0 {
					e.Column = 1
				}
				if e.EndColumn == 0 {
					e.EndColumn = e.Column
				}
				if e.Kind == "" {
					e.Kind = "static-observation"
				}
			}
		}
	}
	for i := range r.Graph.Edges {
		e := &r.Graph.Edges[i].Evidence
		if e.Column == 0 {
			e.Column = 1
		}
		if e.EndLine == 0 {
			e.EndLine = e.Line
		}
		if e.EndColumn == 0 {
			e.EndColumn = e.Column
		}
		if e.Kind == "" {
			e.Kind = "static-relationship"
		}
	}
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
	sort.Slice(r.Suppressions, func(i, j int) bool { return r.Suppressions[i].RuleID < r.Suppressions[j].RuleID })
	sort.Slice(r.Modules, func(i, j int) bool { return r.Modules[i].Module < r.Modules[j].Module })
	r.Risk = 0
	for _, v := range r.Findings {
		score := Rank(v.Severity) * 20
		if score > r.Risk {
			r.Risk = score
		}
	}
	for _, m := range r.Modules {
		if m.Required && (m.Status == "failed" || m.Status == "partial" || m.Status == "unsupported") {
			r.Complete = false
		}
	}
}

func (r *Report) Suppress(rule, reason string) {
	for i := range r.Suppressions {
		if r.Suppressions[i].RuleID == rule {
			r.Suppressions[i].Count++
			return
		}
	}
	r.Suppressions = append(r.Suppressions, Suppression{RuleID: rule, Reason: reason, Count: 1})
}
