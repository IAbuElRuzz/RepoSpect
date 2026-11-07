package acquisition

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"testing"
)

func archive(t *testing.T, name, body string, mode os.FileMode) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(body))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestURLs(t *testing.T) {
	for _, s := range []string{"http://github.com/a/b", "https://evil.invalid/a/b", "https://github.com/a/../b", "https://user:pass@github.com/a/b", "https://github.com/a/b?q=x"} {
		if _, err := GitHubURL(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if s, err := GitHubURL("https://github.com/example/repo.git"); err != nil || s != "https://codeload.github.com/example/repo/zip/HEAD" {
		t.Fatal(s, err)
	}
}
func TestExtraction(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		bad  bool
	}{{"repo/a.txt", 0600, false}, {"repo/../../escape", 0600, true}, {"/repo/a", 0600, true}, {"repo/link", os.ModeSymlink | 0700, true}, {"repo/.git/config", 0600, true}, {"repo/C:drive", 0600, true}} {
		t.Run(tc.name, func(t *testing.T) {
			err := extract(context.Background(), archive(t, tc.name, "inert", tc.mode), t.TempDir())
			if (err != nil) != tc.bad {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}
func FuzzExtract(f *testing.F) {
	f.Add([]byte("invalid zip"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 100000 {
			t.Skip()
		}
		extract(context.Background(), data, t.TempDir())
	})
}
