package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestCLI(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{{[]string{"scan", "../../testdata/suspicious", "--format", "json"}, 0}, {[]string{"scan", "../../testdata/suspicious", "--fail-on", "high"}, 1}, {[]string{"scan", "--fail-on", "invalid"}, 2}, {[]string{"image", "scan", "nginx"}, 2}, {[]string{"scan", "https://example.invalid/repo"}, 2}} {
		var out, err bytes.Buffer
		code := run(context.Background(), tc.args, &out, &err)
		if code != tc.code {
			t.Fatalf("%v: code %d: %s", tc.args, code, err.String())
		}
		if len(tc.args) > 3 && tc.args[3] == "--format" && !json.Valid(out.Bytes()) {
			t.Fatal("invalid JSON")
		}
	}
}
