package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
)

type Options struct {
	MaxFileBytes, MaxTotalBytes int64
	MaxFiles, MaxDepth          int
	Category                    string
	Suppress                    map[string]string
}

func Defaults() Options {
	return Options{MaxFileBytes: 2 << 20, MaxTotalBytes: 100 << 20, MaxFiles: 20000, MaxDepth: 40}
}

// Scanner consumes data only; implementations must not execute scanned content.
type Scanner interface {
	Scan(context.Context, string) (f.Report, error)
}
type Engine struct{ Options Options }

func Safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return '?'
		}
		return r
	}, s)
}
func stable(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}
func (e Engine) Scan(ctx context.Context, root string) (f.Report, error) {
	r := f.Report{SchemaVersion: "1.1", Findings: []f.Finding{}, Graph: f.Graph{Nodes: []f.Node{}, Edges: []f.Edge{}}, Components: []f.Component{}, Coverage: []string{"bounded local text inspection", "npm script references", "heuristic behavior rules"}, Complete: true, Limitations: []string{"Static indicators do not prove execution or compromise", "No AST, general dataflow or binary analysis; transitive inventory limited to npm locks", "No vulnerability database queried; absence of findings is not a clean bill of health"}}
	root, err := filepath.Abs(root)
	if err != nil {
		return r, err
	}
	st, err := os.Lstat(root)
	if err != nil {
		return r, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return r, fmt.Errorf("scan root must be a real directory")
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return r, err
	}
	defer rootHandle.Close()
	o := e.Options
	if o.MaxFileBytes <= 0 || o.MaxTotalBytes <= 0 || o.MaxFiles <= 0 || o.MaxDepth <= 0 {
		return r, fmt.Errorf("scan limits must be positive")
	}
	files := map[string]string{}
	for _, module := range []string{"discovery", "rules", "dependencies", "trace"} {
		r.Module(module)
	}
	r.Module("osv").Status = "skipped"
	r.Module("osv").Required = false
	skip := func(msg string) {
		r.Issue("discovery", "partial", "input_skipped", "", Safe(msg))
		if len(r.Limitations) < 70 {
			r.Limitations = append(r.Limitations, Safe(msg))
		}
	}
	visited := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > o.MaxFiles+1 {
			skip("Traversal entry limit reached")
			return fs.SkipAll
		}
		if walkErr != nil {
			skip("Unreadable path: " + path)
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.Type()&os.ModeSymlink != 0 {
			skip("Skipped symlink: " + rel)
			return nil
		}
		if d.IsDir() {
			if rel != "." {
				switch d.Name() {
				case ".git", "node_modules", "vendor", ".venv", "venv":
					skip("Excluded directory: " + rel)
					return filepath.SkipDir
				}
				if strings.Count(rel, "/")+1 > o.MaxDepth {
					skip("Depth limit: " + rel)
					return filepath.SkipDir
				}
			}
			return nil
		}
		if r.Files >= o.MaxFiles {
			skip("File count limit reached")
			return fs.SkipAll
		}
		info, err := d.Info()
		if err != nil {
			skip("Cannot stat: " + rel)
			return nil
		}
		if !info.Mode().IsRegular() {
			skip("Skipped special file: " + rel)
			return nil
		}
		if info.Size() > o.MaxFileBytes {
			skip("File size limit: " + rel)
			return nil
		}
		if r.Bytes+info.Size() > o.MaxTotalBytes {
			skip("Total byte limit reached")
			return fs.SkipAll
		}
		handle, err := rootHandle.Open(filepath.FromSlash(rel))
		if err != nil {
			skip("Cannot open: " + rel)
			return nil
		}
		opened, err := handle.Stat()
		if err != nil || !os.SameFile(info, opened) {
			handle.Close()
			skip("File changed during scan: " + rel)
			return nil
		}
		data, readErr := io.ReadAll(io.LimitReader(handle, o.MaxFileBytes+1))
		handle.Close()
		if readErr != nil {
			skip("Cannot read: " + rel)
			return nil
		}
		if int64(len(data)) > o.MaxFileBytes {
			skip("File grew beyond limit: " + rel)
			return nil
		}
		if r.Bytes+int64(len(data)) > o.MaxTotalBytes {
			skip("Total byte limit reached during read")
			return fs.SkipAll
		}
		r.Bytes += int64(len(data))
		r.Files++
		if strings.IndexByte(string(data), 0) >= 0 {
			skip("Binary content not analyzed: " + rel)
			return nil
		}
		files[rel] = string(data)
		return nil
	})
	if err != nil {
		return r, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		body := files[name]
		r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: name, Kind: "file", Label: Safe(name)})
		sc := bufio.NewScanner(strings.NewReader(body))
		sc.Buffer(make([]byte, 4096), int(o.MaxFileBytes)+1)
		line := 0
		matched := map[string]bool{}
		for sc.Scan() {
			line++
			s := sc.Text()
			for _, rule := range Rules {
				if matched[rule.ID] {
					continue
				}
				if o.Category != "" && !categoryMatch(o.Category, rule.Category) {
					continue
				}
				if (rule.Category == "infra" && !infraFile(name)) || (rule.Category == "cicd" && !strings.HasPrefix(name, ".github/workflows/")) || (rule.Category == "agents" && !agentFile(name)) {
					continue
				}
				if rule.ID == "RS010" && pinnedAction(s) {
					continue
				}
				match := rule.Pattern.FindStringIndex(s)
				if match == nil {
					continue
				}
				matched[rule.ID] = true
				if reason := o.Suppress[rule.ID]; reason != "" {
					r.Suppress(rule.ID, reason)
					continue
				}
				r.Findings = append(r.Findings, f.Finding{ID: "RS-" + stable(rule.ID, name, fmt.Sprint(line)), RuleID: rule.ID, Severity: rule.Severity, Confidence: "medium", Category: rule.Category, Description: rule.Description, Evidence: []f.Evidence{{File: name, Line: line, Description: rule.Description, Column: match[0] + 1, EndLine: line, EndColumn: match[1] + 1, Kind: "lexical-match", Provenance: "repospect/RE2"}}, Impact: rule.Impact, Remediation: rule.Remediation, Source: "repospect/static"})
				f.Identify(&r.Findings[len(r.Findings)-1], s)
			}
		}
		if err := sc.Err(); err != nil {
			skip("Line parsing failed: " + name)
		}
	}
	inventory(&r, files)
	buildGraph(&r, files, o)
	if len(files) <= 500 {
		correlate(&r, files, o)
	} else {
		r.Issue("trace", "partial", "graph_budget", "", "Cross-file correlation skipped above 500 files")
	}
	// Findings annotate files. These edges are static observations, not dataflow claims.
	for _, finding := range r.Findings {
		ev := finding.Evidence[0]
		r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: finding.ID, Kind: "indicator", Label: finding.Description})
		r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: ev.File, To: finding.ID, Kind: "contains", Relationship: "confirmed", Evidence: ev})
	}
	for i := range r.Graph.Nodes {
		r.Graph.Nodes[i].ID = "node-" + stable(r.Graph.Nodes[i].ID)
	}
	for i := range r.Graph.Edges {
		r.Graph.Edges[i].From = "node-" + stable(r.Graph.Edges[i].From)
		r.Graph.Edges[i].To = "node-" + stable(r.Graph.Edges[i].To)
	}

	r.Module("discovery").Inputs = visited - 1
	r.Module("discovery").Analyzed = r.Files
	r.Module("rules").Inputs = len(files)
	r.Module("rules").Analyzed = len(files)
	r.Normalize()
	for _, finding := range r.Findings {
		score := f.Rank(finding.Severity) * 20
		if score > r.Risk {
			r.Risk = score
		}
	}
	return r, nil
}
func categoryMatch(want, got string) bool {
	switch want {
	case "secrets":
		return got == "secret" || got == "credential-access"
	case "install":
		return got == "install" || got == "behavior" || got == "process" || got == "credential-access"
	case "deps":
		return got == "dependency"
	}
	return want == got
}
func infraFile(s string) bool {
	return strings.Contains(s, "Dockerfile") || strings.HasSuffix(s, ".yaml") || strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".tf")
}
func agentFile(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "mcp") || strings.Contains(s, ".claude/") || strings.Contains(s, ".codex/") || strings.Contains(s, ".cursor/") || strings.HasSuffix(s, "agents.md") || strings.HasSuffix(s, "claude.md")
}

var shaAction = regexp.MustCompile(`@[a-fA-F0-9]{40}(\s|$)`)

func pinnedAction(s string) bool { return shaAction.MatchString(s) }
func addFinding(r *f.Report, o Options, rule, severity, category, file string, line int, desc, impact, remediation string) {
	if o.Category != "" && !categoryMatch(o.Category, category) {
		return
	}
	if o.Suppress[rule] != "" {
		r.Suppress(rule, o.Suppress[rule])
		return
	}
	r.Findings = append(r.Findings, f.Finding{ID: "RS-" + stable(rule, file, fmt.Sprint(line), desc), RuleID: rule, Severity: severity, Confidence: "high", Category: category, Description: desc, Evidence: []f.Evidence{{File: file, Line: line, Description: desc}}, Impact: impact, Remediation: remediation, Source: "repospect/static"})
	f.Identify(&r.Findings[len(r.Findings)-1], desc)
}
func jsonLine(body, key string) int {
	i := strings.Index(body, fmt.Sprintf("%q", key))
	if i < 0 {
		return 1
	}
	return strings.Count(body[:i], "\n") + 1
}
func buildGraph(r *f.Report, files map[string]string, o Options) {
	scripts := map[string]map[string]string{}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		if filepath.Base(name) == "package.json" {
			r.Module("trace").Inputs++
			r.Module("dependencies").Inputs++
			var p struct {
				Scripts      map[string]string `json:"scripts"`
				Dependencies map[string]string `json:"dependencies"`
				Dev          map[string]string `json:"devDependencies"`
			}
			if err := json.Unmarshal([]byte(body), &p); err != nil {
				r.Issue("trace", "partial", "invalid_manifest", name, "Invalid package manifest")
				r.Limitations = append(r.Limitations, "Invalid package manifest: "+Safe(name))
				continue
			}
			scripts[name] = p.Scripts
			r.Module("trace").Analyzed++
			r.Module("dependencies").Analyzed++
			keys := []string{}
			for key := range p.Scripts {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if len(keys) > 1000 {
				keys = keys[:1000]
				r.Complete = false
				r.Limitations = append(r.Limitations, "Manifest script limit: "+Safe(name))
			}
			for _, key := range keys {
				cmd := p.Scripts[key]
				id := name + "#" + key
				line := jsonLine(body, key)
				ev := f.Evidence{File: name, Line: line, Description: "Manifest script definition"}
				r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: id, Kind: "script", Label: Safe(name + ": " + key)})
				r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: name, To: id, Kind: "defines", Relationship: "confirmed", Evidence: ev})
				switch key {
				case "preinstall", "install", "postinstall", "prepare":
					addFinding(r, o, "RS100", "MEDIUM", "install", name, line, "Automatic npm lifecycle hook: "+key, "Package manager operations may execute repository code", "Review the script; use --ignore-scripts until trusted")
				}
				for _, target := range referencedFiles(cmd, filepath.Dir(name), files) {
					r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: id, To: target, Kind: "references", Relationship: "inferred", Evidence: ev})
				}

			}
			for _, deps := range []map[string]string{p.Dependencies, p.Dev} {
				for dep, version := range deps {
					r.Components = append(r.Components, f.Component{Name: Safe(dep), Version: Safe(version), Ecosystem: "npm"})
				}
			}
		}
		if filepath.Base(name) == "setup.py" || filepath.Base(name) == "pyproject.toml" {
			addFinding(r, o, "RS101", "INFO", "install", name, 1, "Python installation/build entry point", "Build backends or setup scripts can execute code", "Inspect backend and build requirements before installation")
		}
		if filepath.Base(name) == "go.mod" {
			sc := bufio.NewScanner(strings.NewReader(body))
			sc.Buffer(make([]byte, 4096), int(o.MaxFileBytes)+1)
			inRequire := false
			for sc.Scan() {
				line := strings.TrimSpace(strings.SplitN(sc.Text(), "//", 2)[0])
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				if fields[0] == "require" {
					if len(fields) == 2 && fields[1] == "(" {
						inRequire = true
						continue
					}
					fields = fields[1:]
				} else if !inRequire {
					if fields[0] == "replace" {
						r.Complete = false
						r.Limitations = append(r.Limitations, "Go replace directives not resolved: "+Safe(name))
					}
					continue
				}
				if len(fields) == 0 {
					continue
				}
				if fields[0] == ")" {
					inRequire = false
					continue
				}
				if len(fields) >= 2 {
					r.Components = append(r.Components, f.Component{Name: Safe(fields[0]), Version: Safe(fields[1]), Ecosystem: "Go"})
				}
			}
			if sc.Err() != nil {
				r.Complete = false
				r.Limitations = append(r.Limitations, "Go manifest line parsing failed: "+Safe(name))
			}
		}

	}

	shellGraph(r, files, scripts)
	sort.Slice(r.Components, func(i, j int) bool {
		a, b := r.Components[i], r.Components[j]
		return a.Ecosystem+a.Name+a.Version < b.Ecosystem+b.Name+b.Version
	})
}
func commandReference(cmd, target string) bool {
	for _, token := range strings.FieldsFunc(cmd, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`;|&()'"`, r) }) {
		if strings.TrimPrefix(token, "./") == target {
			return true
		}
	}
	return false
}

func referencedFiles(cmd, base string, files map[string]string) []string {
	seen := map[string]bool{}
	for _, token := range strings.FieldsFunc(cmd, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune(`;|&()'"`, r) }) {
		token = strings.TrimPrefix(token, "./")
		target := filepath.ToSlash(filepath.Clean(filepath.Join(base, token)))
		if _, ok := files[target]; !ok {
			target = token
		}
		if _, ok := files[target]; ok {
			seen[target] = true
		}
	}
	targets := []string{}
	for t := range seen {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets
}
