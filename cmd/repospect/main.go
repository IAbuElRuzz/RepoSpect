package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/IAbuElRuzz/RepoSpect/internal/acquisition"
	"github.com/IAbuElRuzz/RepoSpect/internal/dependencies"
	"github.com/IAbuElRuzz/RepoSpect/internal/reporting"
	"github.com/IAbuElRuzz/RepoSpect/internal/revision"
	"github.com/IAbuElRuzz/RepoSpect/internal/scanner"
	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
)

var version = "0.1.0-dev"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(errOut, "repospect:", scanner.Safe(err.Error())); return 2 }
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprintln(out, "RepoSpect — Inspect before you execute.\nUsage: repospect <scan|trace|deps|install-audit> [path] [flags]\n       repospect <infra|secrets|cicd|agents> scan [path] [flags]\nFlags: --format text|json|sarif|sbom|mermaid|dot --offline --no-color\n       --fail-on info|low|medium|high|critical --config FILE --timeout 30s --osv\nExit: 0 completed, 1 policy threshold, 2 error, 3 incomplete coverage\nAll scans are local and static. See docs/LIMITATIONS.md.")
		return 0
	}
	cmd := args[0]
	args = args[1:]
	if cmd == "version" || cmd == "--version" {
		fmt.Fprintln(out, version)
		return 0
	}
	category := ""
	switch cmd {
	case "scan", "trace":
	case "deps":
		category = "deps"
	case "install-audit":
		category = "install"
	case "infra", "secrets", "cicd", "agents":
		category = cmd
		if len(args) == 0 || args[0] != "scan" {
			return fail(errors.New("expected scan subcommand"))
		}
		args = args[1:]
	case "image":
		return fail(errors.New("OCI image scanning is not implemented; no image was pulled or executed"))
	case "diff":
		return diff(ctx, args, out, errOut)
	case "explain":
		return fail(errors.New("use finding descriptions and remediation in scan JSON; persistent finding lookup is not implemented"))
	default:
		return fail(errors.New("unknown command; use --help"))
	}
	flags := flag.NewFlagSet(cmd, flag.ContinueOnError)
	flags.SetOutput(errOut)
	format := flags.String("format", "text", "report format")
	threshold := flags.String("fail-on", "", "severity threshold")
	config := flags.String("config", "", "JSON suppression configuration")
	timeout := flags.Duration("timeout", 30*time.Second, "scan timeout")
	osv := flags.Bool("osv", false, "send package names and exact versions to OSV")
	offline := flags.Bool("offline", false, "forbid network access")
	flags.Bool("no-color", true, "plain terminal output")
	// Accept flags before or after a single path, without interpreting path contents as commands.
	path := "."
	positionals := []string{}
	reordered := []string{}
	valueFlags := map[string]bool{"--format": true, "--fail-on": true, "--config": true, "--timeout": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			reordered = append(reordered, a)
			if valueFlags[a] {
				if i+1 >= len(args) {
					return fail(errors.New("missing flag value"))
				}
				i++
				reordered = append(reordered, args[i])
			}
		} else {
			positionals = append(positionals, a)
		}
	}
	if err := flags.Parse(reordered); err != nil {
		return 2
	}
	if len(positionals) > 1 {
		return fail(errors.New("expected one path"))
	}
	if len(positionals) == 1 {
		path = positionals[0]
	}

	switch *format {
	case "text", "json", "sarif", "sbom", "mermaid", "dot":
	default:
		return fail(errors.New("unsupported report format"))
	}
	level := -1
	if *threshold != "" {
		level = f.Rank(strings.ToUpper(*threshold))
		if level < 0 {
			return fail(errors.New("invalid severity threshold"))
		}
	}
	if *timeout <= 0 {
		return fail(errors.New("timeout must be positive"))
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	options := scanner.Defaults()
	options.Category = category
	if *config != "" {
		handle, err := os.Open(*config)
		if err != nil {
			return fail(err)
		}
		var c struct {
			Suppress map[string]string `json:"suppress"`
		}
		data, readErr := io.ReadAll(io.LimitReader(handle, 65537))
		handle.Close()
		if readErr != nil {
			return fail(readErr)
		}
		if len(data) > 65536 {
			return fail(errors.New("configuration exceeds 64 KiB"))
		}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&c); err != nil {
			return fail(errors.New("invalid configuration JSON"))
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return fail(errors.New("configuration must contain exactly one JSON object"))
		}

		for id, reason := range c.Suppress {
			if !scanner.KnownRule(id) || strings.TrimSpace(reason) == "" {
				return fail(errors.New("suppression requires a rule ID and documented reason"))
			}
		}
		options.Suppress = c.Suppress
	}
	if strings.Contains(path, "://") {
		if *offline {
			return fail(errors.New("remote acquisition is forbidden in offline mode"))
		}
		snapshot, cleanup, err := acquisition.Fetch(ctx, path)
		if err != nil {
			return fail(err)
		}
		defer cleanup()
		path = snapshot
	}
	report, err := (scanner.Engine{Options: options}).Scan(ctx, path)
	if err != nil {
		return fail(err)
	}
	var enrichmentErr error
	if *osv {
		if *offline {
			return fail(errors.New("--osv conflicts with --offline"))
		}
		enrichmentErr = dependencies.DefaultClient().Check(ctx, &report)
	}
	if len(options.Suppress) > 0 {
		report.Coverage = append(report.Coverage, "Configured suppressions applied; see supplied configuration for reasons")
	}
	if err := reporting.Write(out, report, *format); err != nil {
		return fail(err)
	}
	if enrichmentErr != nil {
		return fail(enrichmentErr)
	}
	if level >= 0 {
		for _, finding := range report.Findings {
			if f.Rank(finding.Severity) >= level {
				return 1
			}
		}
	}
	if !report.Complete {
		return 3
	}
	return 0
}

func diff(ctx context.Context, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(errOut)
	base := flags.String("base", "main", "base revision")
	head := flags.String("head", "HEAD", "head revision")
	format := flags.String("format", "text", "text or json")
	timeout := flags.Duration("timeout", 30*time.Second, "timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*format != "text" && *format != "json") || *timeout <= 0 {
		fmt.Fprintln(errOut, "repospect: invalid diff arguments")
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	result, err := revision.Compare(ctx, ".", *base, *head, scanner.Defaults())
	if err != nil {
		fmt.Fprintln(errOut, "repospect:", scanner.Safe(err.Error()))
		return 2
	}
	if *format == "json" {
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return 2
		}
	} else {
		fmt.Fprintf(out, "Security diff %s -> %s\n%d introduced, %d resolved, %d unchanged\n", result.Base, result.Head, len(result.Introduced), len(result.Resolved), len(result.Unchanged))
		for _, v := range result.Introduced {
			fmt.Fprintf(out, "+ [%s] %s %s:%d\n", v.Severity, v.Description, scanner.Safe(v.Evidence[0].File), v.Evidence[0].Line)
		}
		for _, limit := range result.Limitations {
			fmt.Fprintln(out, " -", limit)
		}
	}
	if !result.Complete {
		return 3
	}
	return 0
}
