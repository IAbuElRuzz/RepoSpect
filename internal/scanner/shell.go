package scanner

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"

	f "github.com/IAbuElRuzz/RepoSpect/pkg/findings"
)

type shellWord struct {
	Text    string
	Dynamic bool
}
type shellCommand struct {
	Words []shellWord
	Line  int
}

// parseShell recognizes simple command lists without evaluating expansions. It
// deliberately rejects compound shell syntax rather than claiming full POSIX parsing.
func parseShell(input string) ([]shellCommand, error) {
	commands := []shellCommand{}
	words := []shellWord{}
	var word strings.Builder
	quote := rune(0)
	active, dynamic, escaped := false, false, false
	line, commandLine := 1, 1
	flushWord := func() {
		if active {
			words = append(words, shellWord{word.String(), dynamic})
			word.Reset()
			active = false
			dynamic = false
		}
	}
	flushCommand := func() {
		flushWord()
		if len(words) > 0 {
			commands = append(commands, shellCommand{Words: words, Line: commandLine})
			words = nil
		}
		commandLine = line
	}
	chars := []rune(input)
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if escaped {
			if c != '\n' {
				word.WriteRune(c)
				active = true
			}
			escaped = false
			if c == '\n' {
				line++
			}
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			} else {
				word.WriteRune(c)
				if c == '\n' {
					line++
				}
			}
			continue
		}
		if c == '\\' {
			escaped = true
			active = true
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			} else {
				word.WriteRune(c)
				if c == '$' || c == '`' {
					dynamic = true
				}
				if c == '\n' {
					line++
				}
			}
			continue
		}
		if c == '\'' || c == '"' {
			if len(words) == 0 && !active {
				commandLine = line
			}
			quote = c
			active = true
			continue
		}
		if c == '#' && !active {
			for i < len(chars) && chars[i] != '\n' {
				i++
			}
			if i < len(chars) {
				flushCommand()
				line++
				commandLine = line
			}
			continue
		}
		if c == '\n' || c == ';' || c == '|' || c == '&' {
			flushCommand()
			if c == '\n' {
				line++
				commandLine = line
			}
			continue
		}
		if unicode.IsSpace(c) {
			flushWord()
			continue
		}
		if c == '(' || c == ')' || c == '{' || c == '}' || c == '<' || c == '>' {
			return commands, fmt.Errorf("compound syntax or redirection is not resolved")
		}
		if !active && len(words) == 0 {
			commandLine = line
		}
		active = true
		if c == '$' || c == '`' {
			dynamic = true
		}
		word.WriteRune(c)
	}
	if quote != 0 || escaped {
		return commands, fmt.Errorf("unterminated shell quote or escape")
	}
	flushCommand()
	return commands, nil
}
func localTarget(base, value string, files map[string]string) (string, bool) {
	if strings.HasPrefix(value, "/") {
		return "", false
	}
	target := path.Clean(path.Join(base, value))
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", false
	}
	_, ok := files[target]
	return target, ok
}

// shellGraph adds syntactically supported invocations; literal references remain
// separately inferred. Neither relationship proves runtime execution.
func shellGraph(r *f.Report, files map[string]string, scripts map[string]map[string]string) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ".sh") || strings.HasPrefix(files[name], "#!/bin/sh") || strings.HasPrefix(files[name], "#!/bin/bash") {
			addShellCommands(r, files, scripts, name, name, path.Dir(name), files[name], 1)
		}
		if hooks, ok := scripts[name]; ok {
			keys := []string{}
			for key := range hooks {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(keys) > 1000 {
					break
				}
				line := jsonLine(files[name], key)
				id := name + "#" + key
				if lifecycle(key) {
					entry := name + "#entry:" + key
					r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: entry, Kind: "entrypoint", Label: "npm lifecycle: " + key})
					r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: entry, To: id, Kind: "invokes", Relationship: "inferred", Evidence: f.Evidence{File: name, Line: line, Kind: "manifest", Description: "npm lifecycle entry point when scripts are enabled; operation-dependent"}})
				}
				addShellCommands(r, files, scripts, id, name, path.Dir(name), hooks[key], line)
			}
		}
	}
}
func lifecycle(key string) bool {
	return key == "preinstall" || key == "install" || key == "postinstall" || key == "prepare"
}
func addShellCommands(r *f.Report, files map[string]string, scripts map[string]map[string]string, from, file, base, body string, start int) {
	commands, err := parseShell(body)
	if err != nil {
		r.Issue("trace", "partial", "unresolved_shell", file, "Shell syntax is outside the supported simple-command subset")
		return
	}
	if len(commands) > 1000 {
		r.Issue("trace", "partial", "command_budget", file, "Command limit reached")
		commands = commands[:1000]
	}
	for index, command := range commands {
		words := command.Words
		if len(words) == 0 {
			continue
		}
		for len(words) > 0 && strings.Contains(words[0].Text, "=") {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		if words[0].Text == "env" {
			words = words[1:]
			for len(words) > 0 && strings.Contains(words[0].Text, "=") {
				words = words[1:]
			}
			if len(words) == 0 {
				continue
			}
		}
		ev := f.Evidence{File: file, Line: start + command.Line - 1, Kind: "shell-syntax", Description: "Statically parsed command; execution not established"}
		id := from + fmt.Sprintf("#command:%d", index)
		r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: id, Kind: "command", Label: "Parsed shell command"})
		r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: from, To: id, Kind: "invokes", Relationship: "confirmed", Evidence: ev})
		unresolved := func() {
			unknown := id + "#unresolved"
			r.Graph.Nodes = append(r.Graph.Nodes, f.Node{ID: unknown, Kind: "unresolved", Label: "Unresolved execution target"})
			r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: id, To: unknown, Kind: "executes", Relationship: "unknown", Evidence: ev})
			r.Issue("trace", "partial", "dynamic_target", file, "Dynamic or unsupported execution target was not resolved")
		}
		if words[0].Dynamic {
			unresolved()
			continue
		}
		exe := words[0].Text
		if exe == "cd" {
			if len(words) != 2 || words[1].Dynamic || strings.HasPrefix(words[1].Text, "/") {
				unresolved()
				continue
			}
			next := path.Clean(path.Join(base, words[1].Text))
			if next == ".." || strings.HasPrefix(next, "../") {
				unresolved()
				continue
			}
			base = next
			continue
		}
		manifest := path.Join(base, "package.json")
		if exe == "npm" || exe == "pnpm" || exe == "yarn" {
			offset := 1
			if len(words) > 1 && (words[1].Text == "run" || words[1].Text == "run-script") {
				offset = 2
			}
			if len(words) > offset && !words[offset].Dynamic {
				key := words[offset].Text
				if _, ok := scripts[manifest][key]; ok {
					r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: id, To: manifest + "#" + key, Kind: "invokes", Relationship: "confirmed", Evidence: ev})
					continue
				}
			}
			unresolved()
			continue
		}
		targetIndex := -1
		switch path.Base(exe) {
		case "node", "nodejs", "python", "python3", "python2", "bash", "sh", "zsh", "source", ".":
			targetIndex = 1
			for targetIndex < len(words) && strings.HasPrefix(words[targetIndex].Text, "-") {
				if words[targetIndex].Text == "-c" || words[targetIndex].Text == "-e" || words[targetIndex].Text == "-m" {
					targetIndex = -1
					break
				}
				targetIndex++
			}
		default:
			if strings.Contains(exe, "/") {
				targetIndex = 0
			}
		}
		if targetIndex >= 0 && targetIndex < len(words) && !words[targetIndex].Dynamic {
			if target, ok := localTarget(base, words[targetIndex].Text, files); ok {
				r.Graph.Edges = append(r.Graph.Edges, f.Edge{From: id, To: target, Kind: "executes", Relationship: "confirmed", Evidence: ev})
				continue
			}
			unresolved()
		} else if targetIndex >= 0 || strings.Contains(exe, "$") || exe == "eval" {
			unresolved()
		}
	}
}
