// Package acquisition downloads bounded GitHub snapshots without invoking Git or checking out code.
package acquisition

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxArchive = 50 << 20

var repositoryPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func GitHubURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("only https://github.com/owner/repository URLs are supported")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("expected owner/repository")
	}
	parts[1] = strings.TrimSuffix(parts[1], ".git")
	for _, p := range parts {
		if !repositoryPart.MatchString(p) || p == "." || p == ".." {
			return "", fmt.Errorf("invalid repository name")
		}
	}
	return "https://codeload.github.com/" + parts[0] + "/" + parts[1] + "/zip/HEAD", nil
}

// Fetch uses anonymous HTTPS only, with no credential helpers, hooks, filters or submodules.
func Fetch(ctx context.Context, raw string) (string, func(), error) {
	endpoint, err := GitHubURL(raw)
	if err != nil {
		return "", nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, err
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("archive redirects are forbidden") }}
	response, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("archive request returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxArchive+1))
	if err != nil {
		return "", nil, err
	}
	if len(data) > maxArchive {
		return "", nil, fmt.Errorf("compressed archive exceeds 50 MiB")
	}
	root, err := os.MkdirTemp("", "repospect-snapshot-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(root) }
	if err := extract(ctx, data, root); err != nil {
		cleanup()
		return "", nil, err
	}
	return root, cleanup, nil
}
func extract(ctx context.Context, data []byte, root string) error {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if len(archive.File) > 20000 {
		return fmt.Errorf("archive file count exceeds limit")
	}
	var total uint64
	seen := map[string]bool{}
	prefix := ""
	for _, entry := range archive.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name
		if strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") {
			return fmt.Errorf("unsafe archive path")
		}
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("archive must have one root directory")
		}
		if prefix == "" {
			prefix = parts[0]
		}
		if parts[0] != prefix {
			return fmt.Errorf("multiple archive roots")
		}
		relative := parts[1]
		if relative == "" {
			continue
		}
		if strings.Contains(relative, ":") || strings.Count(relative, "/") > 40 {
			return fmt.Errorf("unsafe or excessively deep archive path")
		}
		for _, part := range strings.Split(relative, "/") {
			if part == ".." || part == ".git" {
				return fmt.Errorf("forbidden archive path")
			}
		}
		if entry.Mode()&os.ModeSymlink != 0 || (!entry.Mode().IsRegular() && !entry.FileInfo().IsDir()) {
			return fmt.Errorf("archive special files are forbidden")
		}
		dest := filepath.Join(root, filepath.FromSlash(relative))
		rel, err := filepath.Rel(root, dest)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("archive path escapes destination")
		}
		key := strings.ToLower(filepath.Clean(dest))
		if seen[key] {
			return fmt.Errorf("duplicate archive path")
		}
		seen[key] = true
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0700); err != nil {
				return err
			}
			continue
		}
		if entry.UncompressedSize64 > 2<<20 {
			return fmt.Errorf("archive member exceeds 2 MiB")
		}
		total += entry.UncompressedSize64
		if total > 100<<20 {
			return fmt.Errorf("expanded archive exceeds 100 MiB")
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return err
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			input.Close()
			return err
		}
		n, copyErr := io.Copy(output, io.LimitReader(input, 2<<20+1))
		input.Close()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > 2<<20 {
			return fmt.Errorf("archive member overflow")
		}
	}
	return nil
}
