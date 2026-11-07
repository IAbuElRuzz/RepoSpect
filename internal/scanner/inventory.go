package scanner

import (
	"bufio"
	"encoding/json"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var requirement = regexp.MustCompile(`^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9.+_-]+)(?:\s*;.*)?$`)

func inventory(r *f.Report, files map[string]string) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		switch filepath.Base(name) {
		case "package-lock.json":
			r.Module("dependencies").Inputs++
			var lock struct {
				LockfileVersion int `json:"lockfileVersion"`
				Packages        map[string]struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"packages"`
			}
			if err := json.Unmarshal([]byte(body), &lock); err != nil {
				r.Issue("dependencies", "partial", "invalid_lockfile", name, "Invalid npm lockfile")
				continue
			}
			if lock.LockfileVersion < 2 || lock.LockfileVersion > 3 {
				r.Issue("dependencies", "unsupported", "unsupported_lock_version", name, "Unsupported npm lockfile version")
				continue
			}
			r.Module("dependencies").Analyzed++
			for path, p := range lock.Packages {
				if path == "" || p.Version == "" {
					continue
				}
				dep := p.Name
				if dep == "" {
					i := strings.LastIndex(path, "node_modules/")
					if i < 0 {
						continue
					}
					dep = path[i+len("node_modules/"):]
				}
				r.Components = append(r.Components, f.Component{Name: Safe(dep), Version: Safe(p.Version), Ecosystem: "npm"})
			}
		case "requirements.txt":
			r.Module("dependencies").Inputs++
			sc := bufio.NewScanner(strings.NewReader(body))
			for sc.Scan() {
				line := strings.TrimSpace(strings.SplitN(sc.Text(), " #", 2)[0])
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				match := requirement.FindStringSubmatch(line)
				if match == nil {
					r.Issue("dependencies", "partial", "unresolved_requirement", name, "Python requirement is not an exact supported pin")
					continue
				}
				r.Components = append(r.Components, f.Component{Name: Safe(match[1]), Version: Safe(match[2]), Ecosystem: "PyPI"})
			}
			if sc.Err() != nil {
				r.Issue("dependencies", "partial", "parser_limit", name, "Python requirement line exceeds parser capacity")
			} else {
				r.Module("dependencies").Analyzed++
			}
		case "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "uv.lock":
			r.Module("dependencies").Inputs++
			r.Issue("dependencies", "unsupported", "unsupported_lockfile", name, "Unsupported dependency lockfile")
		}
	}
}
