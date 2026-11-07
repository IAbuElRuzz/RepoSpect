package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestFixtureTrace(t *testing.T) {
	r, err := (Engine{Defaults()}).Scan(context.Background(), "../../testdata/suspicious")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, v := range r.Findings {
		found[v.RuleID] = true
	}
	for _, id := range []string{"RS001", "RS002", "RS100", "RS200"} {
		if !found[id] {
			t.Errorf("missing %s", id)
		}
	}
	linked := false
	for _, e := range r.Graph.Edges {
		if e.From == "node-"+stable("package.json#preinstall") && e.To == "node-"+stable("scripts/install.js") && e.Relationship == "inferred" {
			linked = true
		}
		if e.Evidence.Line < 1 {
			t.Error("edge missing evidence")
		}
	}
	if !linked {
		t.Fatal("missing lifecycle reference")
	}
}
func TestLimitsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	put(t, outside, "secret", "eval(secret)")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	put(t, root, "large", strings.Repeat("x", 200))
	o := Defaults()
	o.MaxFileBytes = 100
	r, err := (Engine{o}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.Findings) != 0 {
		t.Fatal("skips not reported safely")
	}
}
func TestRedactionAndDeterminism(t *testing.T) {
	root := t.TempDir()
	secret := "ghp_" + strings.Repeat("a", 36)
	put(t, root, "token.txt", secret)
	a, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := (Engine{Defaults()}).Scan(context.Background(), root)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatal("nondeterministic report")
	}
	if strings.Contains(string(x), secret) {
		t.Fatal("secret leaked")
	}
	if len(a.Findings) != 1 || a.Findings[0].RuleID != "RS012" {
		t.Fatal("missing secret")
	}
}
func TestBenignAndSuppression(t *testing.T) {
	root := t.TempDir()
	put(t, root, "main.go", "package main\nfunc main() {}\n")
	r, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("benign scan: %v %v", r.Findings, err)
	}
	put(t, root, "x.py", "eval(x)")
	o := Defaults()
	o.Suppress = map[string]string{"RS003": "reviewed fixture"}
	r, err = (Engine{o}).Scan(context.Background(), root)
	if err != nil || len(r.Findings) != 0 {
		t.Fatal("suppression failed")
	}
}
func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Engine{Defaults()}).Scan(ctx, t.TempDir())
	if err == nil {
		t.Fatal("expected cancellation")
	}
}
func TestMalformedManifest(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package.json", "{invalid")
	r, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil || r.Complete {
		t.Fatal("malformed manifest must mark partial coverage")
	}
}
func TestTerminalSanitization(t *testing.T) {
	if Safe("x\x1b[31m\u202ey") != "x?[31m?y" {
		t.Fatal("controls not sanitized")
	}
}
func FuzzCommandReference(f *testing.F) {
	f.Add("node ./scripts/install.js", "scripts/install.js")
	f.Fuzz(func(t *testing.T, cmd, target string) { commandReference(cmd, target) })
}
func BenchmarkFixture(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := (Engine{Defaults()}).Scan(context.Background(), "../../testdata/suspicious"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestInventory(t *testing.T) {
	root := t.TempDir()
	put(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"1.2.3"}}}`)
	put(t, root, "requirements.txt", "demo==2.3.4\n")
	put(t, root, "go.mod", "module example.invalid/demo\nrequire example.invalid/lib v1.0.0\n")
	r, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Components) != 3 {
		t.Fatalf("inventory: %+v", r.Components)
	}
}
func TestRuleTable(t *testing.T) {
	for _, tc := range []struct {
		name, body, id string
		want           bool
	}{
		{"Dockerfile", "USER root", "RS008", true},
		{"compose.yaml", "privileged: true", "RS007", true},
		{".github/workflows/build.yml", "uses: org/action@main", "RS010", true},
		{".github/workflows/build.yml", "uses: org/action@0123456789abcdef0123456789abcdef01234567", "RS010", false},
		{".github/workflows/build.yml", "on: pull_request_target", "RS009", true},
		{".mcp.json", `{"command":"sh"}`, "RS011", true},
		{"data.json", `{"command":"sh"}`, "RS011", false},
		{"script.py", "base64.b64decode(payload)", "RS004", true},
	} {
		t.Run(tc.name+tc.id, func(t *testing.T) {
			root := t.TempDir()
			put(t, root, tc.name, tc.body)
			r, err := (Engine{Defaults()}).Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, v := range r.Findings {
				found = found || v.RuleID == tc.id
			}
			if found != tc.want {
				t.Fatalf("%s found=%t want=%t", tc.id, found, tc.want)
			}
		})
	}
}

func TestGraphEndpoints(t *testing.T) {
	root := t.TempDir()
	put(t, root, "bad\u202ename.py", "eval(payload)")
	r, err := (Engine{Defaults()}).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, n := range r.Graph.Nodes {
		ids[n.ID] = true
	}
	for _, e := range r.Graph.Edges {
		if !ids[e.From] || !ids[e.To] {
			t.Fatalf("dangling graph edge: %+v", e)
		}
	}
}
