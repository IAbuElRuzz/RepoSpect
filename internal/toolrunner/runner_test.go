package toolrunner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHelperProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "repospect-helper" {
		return
	}
	switch os.Args[len(os.Args)-2] {
	case "ok":
		if os.Getenv("REPOSPECT_SECRET_CANARY") != "" {
			os.Exit(4)
		}
		fmt.Print(`{"ok":true}`)
	case "large":
		fmt.Print(strings.Repeat("x", 200))
	case "slow":
		time.Sleep(10 * time.Second)
	case "bad":
		fmt.Fprint(os.Stderr, "sensitive tool output")
		os.Exit(9)
	}
	os.Exit(0)
}
func TestRun(t *testing.T) {
	t.Setenv("REPOSPECT_SECRET_CANARY", "do-not-inherit")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode    string
		timeout time.Duration
		bad     bool
	}{{"ok", time.Second, false}, {"large", time.Second, true}, {"slow", 30 * time.Millisecond, true}, {"bad", time.Second, true}} {
		t.Run(tc.mode, func(t *testing.T) {
			r, err := Run(context.Background(), Request{Executable: exe, Args: []string{"-test.run=^TestHelperProcess$", "--", tc.mode, "repospect-helper"}, Enabled: true, Timeout: tc.timeout, MaxOutput: 100})
			if (err != nil) != tc.bad {
				t.Fatalf("error %v", err)
			}
			if !tc.bad {
				var result struct {
					OK bool `json:"ok"`
				}
				if err := DecodeJSON(r.Output, &result); err != nil || !result.OK {
					t.Fatal("invalid result", err)
				}
			}
			if err != nil && strings.Contains(err.Error(), "sensitive") {
				t.Fatal("tool diagnostic leaked")
			}
		})
	}
}
func TestNotEnabled(t *testing.T) {
	if _, err := Run(context.Background(), Request{}); err == nil {
		t.Fatal("unapproved tool execution accepted")
	}
}
func TestDecode(t *testing.T) {
	for _, s := range []string{`{"unknown":true}`, `{"ok":true} {}`, `malformed`} {
		var result struct {
			OK bool `json:"ok"`
		}
		if DecodeJSON([]byte(s), &result) == nil {
			t.Fatal("invalid scanner output accepted")
		}
	}
}
