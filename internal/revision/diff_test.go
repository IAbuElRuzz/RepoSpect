package revision

import (
	"context"
	"github.com/IAbuElRuzz/RepoSpect/internal/scanner"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCompare(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	ctx := context.Background()
	call := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s %v", args, data, err)
		}
	}
	call("init")
	call("config", "user.name", "Fixture")
	call("config", "user.email", "fixture@example.invalid")
	path := filepath.Join(root, "sample.py")
	os.WriteFile(path, []byte("# harmless\n"), 0600)
	call("add", "sample.py")
	call("commit", "-m", "base")
	os.WriteFile(path, []byte("# eval(payload)\n"), 0600)
	call("commit", "-am", "head")
	r, err := Compare(ctx, root, "HEAD~1", "HEAD", scanner.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Introduced) != 1 || r.Introduced[0].RuleID != "RS003" {
		t.Fatalf("unexpected delta: %+v", r)
	}
	if _, err := Compare(ctx, root, "--help", "HEAD", scanner.Defaults()); err == nil {
		t.Fatal("invalid revision accepted")
	}
}
