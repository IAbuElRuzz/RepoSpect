package reporting

import (
	"encoding/json"
	"fmt"
	"github.com/IAbuElRuzz/RepoSpect/internal/scanner"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
	"io"
	"net/url"
	"strings"
)

type Reporter interface {
	Write(io.Writer, f.Report) error
}

func Write(w io.Writer, r f.Report, format string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	switch format {
	case "json":
		return enc.Encode(r)
	case "sarif":
		results := []any{}
		for _, v := range r.Findings {
			level := "warning"
			if f.Rank(v.Severity) >= 3 {
				level = "error"
			}
			ev := v.Evidence[0]
			results = append(results, map[string]any{"ruleId": v.RuleID, "level": level, "message": map[string]string{"text": v.Description}, "partialFingerprints": map[string]string{"repospect/v1": v.Fingerprint}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": (&url.URL{Path: ev.File}).EscapedPath()}, "region": map[string]int{"startLine": ev.Line}}}}})
		}
		return enc.Encode(map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]string{"name": "RepoSpect", "version": "0.1.0"}}, "results": results, "invocations": []any{map[string]any{"executionSuccessful": r.Complete}}, "properties": map[string]any{"limitations": r.Limitations, "modules": r.Modules}}}})
	case "sbom":
		components := []any{}
		for _, c := range r.Components {
			components = append(components, map[string]string{"type": "library", "name": c.Name, "version": c.Version})
		}
		return enc.Encode(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components, "metadata": map[string]any{"properties": []any{map[string]string{"name": "repospect:coverage", "value": "Declared npm and Go dependencies only; ranges are not resolved versions"}}}})
	case "mermaid", "dot":
		ids := map[string]string{}
		for i, n := range r.Graph.Nodes {
			ids[n.ID] = fmt.Sprintf("n%d", i)
		}
		if format == "dot" {
			fmt.Fprintln(w, "digraph repospect {")
			for _, n := range r.Graph.Nodes {
				fmt.Fprintf(w, "  %s [label=%q];\n", ids[n.ID], n.Label)
			}
			for _, e := range r.Graph.Edges {
				fmt.Fprintf(w, "  %s -> %s [label=%q];\n", ids[e.From], ids[e.To], e.Kind+" ("+e.Relationship+")")
			}
			_, err := fmt.Fprintln(w, "}")
			return err
		}
		fmt.Fprintln(w, "flowchart TD")
		for _, n := range r.Graph.Nodes {
			label := strings.NewReplacer("&", "&amp;", "\"", "&quot;", "<", "&lt;", ">", "&gt;").Replace(n.Label)
			fmt.Fprintf(w, "  %s[\"%s\"]\n", ids[n.ID], label)
		}
		for _, e := range r.Graph.Edges {
			fmt.Fprintf(w, "  %s -->|%s, %s| %s\n", ids[e.From], e.Kind, e.Relationship, ids[e.To])
		}
		return nil
	case "text":
		fmt.Fprintf(w, "RepoSpect — Inspect before you execute.\n%d files, %d findings; risk priority %d/100 (not a probability)\n", r.Files, len(r.Findings), r.Risk)
		for _, v := range r.Findings {
			ev := v.Evidence[0]
			fmt.Fprintf(w, "\n[%s] %s %s\n  %s:%d — %s\n  Remediation: %s\n", v.Severity, v.ID, v.RuleID, scanner.Safe(ev.File), ev.Line, v.Description, v.Remediation)
		}
		if len(r.Graph.Edges) > 0 {
			labels := map[string]string{}
			for _, n := range r.Graph.Nodes {
				labels[n.ID] = n.Label
			}
			fmt.Fprintln(w, "\nStatic relationships:")
			for _, e := range r.Graph.Edges {
				if e.Kind != "contains" {
					fmt.Fprintf(w, "  %s -> %s [%s, %s; %s:%d]\n", labels[e.From], labels[e.To], e.Kind, e.Relationship, scanner.Safe(e.Evidence.File), e.Evidence.Line)
				}
			}
		}
		fmt.Fprintln(w, "\nModule coverage:")
		for _, module := range r.Modules {
			fmt.Fprintf(w, "  %s: %s (%d/%d inputs; %d issues)\n", scanner.Safe(module.Module), module.Status, module.Analyzed, module.Inputs, module.IssueCount)
			for _, issue := range module.Issues {
				fmt.Fprintf(w, "    %s: %s %s\n", issue.Code, scanner.Safe(issue.File), scanner.Safe(issue.Description))
			}
		}
		fmt.Fprintln(w, "\nCoverage limits:")
		for _, s := range r.Limitations {
			fmt.Fprintln(w, " -", s)
		}
		_, err := fmt.Fprintf(w, "Coverage complete within supported analysis: %t\n", r.Complete)
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
