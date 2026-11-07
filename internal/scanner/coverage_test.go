package scanner

import (
	"context"
	"strings"
	"testing"
)

func TestCoverageRecords(t *testing.T) {
	for _, tc := range []struct{ name, body, module, code string }{{"package.json", "{invalid", "trace", "invalid_manifest"}, {"requirements.txt", "demo>=1.0", "dependencies", "unresolved_requirement"}, {"requirements.txt", strings.Repeat("x", 70000), "dependencies", "parser_limit"}, {"package-lock.json", `{"lockfileVersion":99}`, "dependencies", "unsupported_lock_version"}, {"uv.lock", "unsupported", "dependencies", "unsupported_lockfile"}} {
		t.Run(tc.name+tc.code, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, tc.name, tc.body)
			r, err := (Engine{Defaults()}).Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if r.Complete {
				t.Fatal("unsupported/malformed input reported complete")
			}
			found := false
			for _, m := range r.Modules {
				if m.Module == tc.module {
					for _, issue := range m.Issues {
						found = found || issue.Code == tc.code
					}
				}
			}
			if !found {
				t.Fatalf("missing structured issue %s", tc.code)
			}
		})
	}
}
func TestStableFingerprints(t *testing.T) {
	root := t.TempDir()
	put(t, root, "a.py", "eval(payload)\n")
	a, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	put(t, root, "a.py", "# inserted harmless line\neval(payload)\n")
	b, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if a.Findings[0].Fingerprint == "" || a.Findings[0].Fingerprint != b.Findings[0].Fingerprint {
		t.Fatal("line insertion changed semantic identity")
	}
	if a.Findings[0].ID == b.Findings[0].ID {
		t.Fatal("occurrence ID should change with source position")
	}
	ev := b.Findings[0].Evidence[0]
	if ev.Line != 2 || ev.Column != 1 || ev.EndColumn <= ev.Column || ev.Kind != "lexical-match" {
		t.Fatalf("invalid evidence: %+v", ev)
	}
}
