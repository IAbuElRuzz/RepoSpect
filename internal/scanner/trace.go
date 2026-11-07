package scanner

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
)

// correlate joins bounded, literal file references. It does not infer variable values or dataflow.
func correlate(r *f.Report, files map[string]string, o Options) {
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	edgeCount := 0
	for _, name := range names {
		if strings.HasSuffix(name, ".json") {
			continue
		}
		for n, line := range strings.Split(files[name], "\n") {
			for _, token := range strings.FieldsFunc(line, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`;|&()'"`, r) }) {
				token = strings.TrimPrefix(token, "./")
				target := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(name), token)))
				if _, ok := files[target]; !ok {
					target = token
				}
				if _, ok := files[target]; !ok || target == name {
					continue
				}
				if edgeCount >= 10000 {
					r.Complete = false
					r.Limitations = append(r.Limitations, "Cross-file edge limit reached")
					return
				}
				r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: name, To: target, Kind: "references", Relationship: "inferred", Evidence: f.Evidence{File: name, Line: n + 1, Description: "Literal local path reference; invocation not proven"}})
				edgeCount++
			}
		}
	}
	// Bound expensive correlation independently of total byte limits.
	outgoing := map[string][]string{}
	for _, edge := range r.Graph.Edges {
		outgoing[edge.From] = append(outgoing[edge.From], edge.To)
	}
	for _, node := range r.Graph.Nodes {
		if node.Kind != "script" {
			continue
		}
		hook := node.ID[strings.LastIndex(node.ID, "#")+1:]
		if hook != "preinstall" && hook != "install" && hook != "postinstall" && hook != "prepare" {
			continue
		}
		seen := map[string]bool{}
		queue := []string{node.ID}
		credentials, network := false, false
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			if seen[current] {
				continue
			}
			seen[current] = true
			for _, finding := range r.Findings {
				if finding.Evidence[0].File == current {
					credentials = credentials || finding.Category == "credential-access"
					network = network || finding.Category == "network"
				}
			}
			queue = append(queue, outgoing[current]...)
		}
		if credentials && network {
			file := node.ID[:strings.LastIndex(node.ID, "#")]
			addFinding(r, o, "RS200", "HIGH", "behavior", file, jsonLine(files[file], hook), fmt.Sprintf("Lifecycle hook %s references files with credential and network indicators", hook), "Possible credential exposure along inferred file references; no dataflow or execution is proven", "Review the complete referenced chain before enabling installation scripts")
		}
	}
}
