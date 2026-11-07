// Package toolrunner is the opt-in execution boundary for trusted scanner tools.
// It is never used to launch code, commands or executables from a scanned tree.
package toolrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Request struct {
	Executable string
	Args       []string
	Enabled    bool
	Timeout    time.Duration
	MaxOutput  int
}
type Result struct {
	Output   []byte
	Duration time.Duration
}
type bounded struct {
	buffer bytes.Buffer
	max    int
}

func (b *bounded) Write(data []byte) (int, error) {
	if b.buffer.Len()+len(data) > b.max {
		return 0, fmt.Errorf("tool output limit exceeded")
	}
	return b.buffer.Write(data)
}

// Run requires an explicit trusted absolute executable path. No shell, project
// working directory, inherited credentials, or project-owned config is supplied.
func Run(ctx context.Context, req Request) (Result, error) {
	if !req.Enabled {
		return Result{}, fmt.Errorf("external tool is not explicitly enabled")
	}
	if !filepath.IsAbs(req.Executable) || req.Timeout <= 0 || req.MaxOutput <= 0 || req.MaxOutput > 32<<20 {
		return Result{}, fmt.Errorf("invalid external tool configuration")
	}
	executable, err := filepath.EvalSymlinks(req.Executable)
	if err != nil {
		return Result{}, fmt.Errorf("trusted tool is unavailable")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("trusted tool is not a regular executable")
	}
	work, err := os.MkdirTemp("", "repospect-tool-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(work)
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, req.Args...)
	command.Dir = work
	command.Env = []string{"HOME=" + work, "USERPROFILE=" + work, "XDG_CONFIG_HOME=" + work, "XDG_CACHE_HOME=" + work, "TMPDIR=" + work, "TMP=" + work, "TEMP=" + work, "LANG=C", "LC_ALL=C"}
	if systemRoot := os.Getenv("SystemRoot"); systemRoot != "" {
		command.Env = append(command.Env, "SystemRoot="+systemRoot)
	}
	command.WaitDelay = time.Second
	out := &bounded{max: req.MaxOutput}
	command.Stdout = out
	command.Stderr = io.Discard
	start := time.Now()
	err = command.Run()
	result := Result{Duration: time.Since(start)}
	if err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("trusted tool canceled or timed out: %w", ctx.Err())
		}
		return result, fmt.Errorf("trusted tool failed or exceeded output limit")
	}
	result.Output = out.buffer.Bytes()
	return result, nil
}

// DecodeJSON rejects trailing documents, unknown fields and malformed output.
func DecodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid scanner JSON output")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fmt.Errorf("scanner output contains trailing data")
	}
	return nil
}
