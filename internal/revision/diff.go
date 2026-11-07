// Package revision compares static scans of bounded Git archive snapshots.
package revision

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"github.com/IAbuElRuzz/RepoSpect/internal/scanner"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Result struct {
	Base        string      `json:"base"`
	Head        string      `json:"head"`
	Introduced  []f.Finding `json:"introduced"`
	Resolved    []f.Finding `json:"resolved"`
	Unchanged   []f.Finding `json:"unchanged"`
	Complete    bool        `json:"complete"`
	Limitations []string    `json:"limitations"`
}
type limitBuffer struct {
	buffer bytes.Buffer
	max    int
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > b.max {
		return 0, fmt.Errorf("Git output limit exceeded")
	}
	return b.buffer.Write(p)
}
func git(ctx context.Context, root string, limit int, args ...string) ([]byte, error) {
	base := []string{"--no-pager", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", root}
	command := exec.CommandContext(ctx, "git", append(base, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_ATTR_NOSYSTEM=1", "LC_ALL=C"}
	out := &limitBuffer{max: limit}
	command.Stdout = out
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("Git snapshot command failed: %w", err)
	}
	return out.buffer.Bytes(), nil
}
func snapshot(ctx context.Context, root, ref string) (string, string, func(), error) {
	data, err := git(ctx, root, 1024, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", "", nil, err
	}
	sha := strings.TrimSpace(string(data))
	if !regexp.MustCompile(`^[a-f0-9]{40,64}$`).MatchString(sha) {
		return "", "", nil, fmt.Errorf("invalid resolved commit")
	}
	data, err = git(ctx, root, 110<<20, "archive", "--format=tar", sha)
	if err != nil {
		return "", "", nil, err
	}
	dir, err := os.MkdirTemp("", "repospect-revision-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	if err := extract(ctx, data, dir); err != nil {
		cleanup()
		return "", "", nil, err
	}
	return dir, sha, cleanup, nil
}
func extract(ctx context.Context, data []byte, root string) error {
	reader := tar.NewReader(bytes.NewReader(data))
	total := int64(0)
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		count++
		if count > 20000 {
			return fmt.Errorf("snapshot file count limit")
		}
		name := h.Name
		if strings.Contains(name, "\\") || strings.Contains(name, ":") || filepath.IsAbs(name) || strings.Count(name, "/") > 40 {
			return fmt.Errorf("unsafe snapshot path")
		}
		clean := filepath.Clean(name)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("snapshot traversal")
		}
		dest := filepath.Join(root, clean)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0700); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > 2<<20 {
				return fmt.Errorf("snapshot file size limit")
			}
			total += h.Size
			if total > 100<<20 {
				return fmt.Errorf("snapshot total size limit")
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return err
			}
			output, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			_, err = io.CopyN(output, reader, h.Size)
			closeErr := output.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("snapshot contains unsupported link or special file")
		}
	}
}
func Compare(ctx context.Context, root, base, head string, o scanner.Options) (Result, error) {
	result := Result{Introduced: []f.Finding{}, Resolved: []f.Finding{}, Unchanged: []f.Finding{}}
	a, sha, clean, err := snapshot(ctx, root, base)
	if err != nil {
		return result, err
	}
	defer clean()
	result.Base = sha
	b, sha, clean, err := snapshot(ctx, root, head)
	if err != nil {
		return result, err
	}
	defer clean()
	result.Head = sha
	before, err := (scanner.Engine{Options: o}).Scan(ctx, a)
	if err != nil {
		return result, err
	}
	after, err := (scanner.Engine{Options: o}).Scan(ctx, b)
	if err != nil {
		return result, err
	}
	result.Complete = before.Complete && after.Complete
	result.Limitations = append(before.Limitations, after.Limitations...)
	// Match by rule, path and description, avoiding churn from unrelated line insertions.
	key := func(v f.Finding) string {
		if v.Fingerprint != "" {
			return v.Fingerprint
		}
		return v.RuleID + "\x00" + v.Evidence[0].File + "\x00" + v.Description
	}
	old := map[string]f.Finding{}
	for _, v := range before.Findings {
		old[key(v)] = v
	}
	for _, v := range after.Findings {
		k := key(v)
		if _, ok := old[k]; ok {
			result.Unchanged = append(result.Unchanged, v)
			delete(old, k)
		} else {
			result.Introduced = append(result.Introduced, v)
		}
	}
	for _, v := range old {
		result.Resolved = append(result.Resolved, v)
	}
	sort.Slice(result.Resolved, func(i, j int) bool { return result.Resolved[i].ID < result.Resolved[j].ID })
	return result, nil
}
