package scanner

import "regexp"

type Rule struct {
	ID, Severity, Category, Description, Impact, Remediation string
	Pattern                                                  *regexp.Regexp
}

func rule(id, severity, category, pattern, description, impact, remediation string) Rule {
	return Rule{id, severity, category, description, impact, remediation, regexp.MustCompile(pattern)}
}

// Rules deliberately describe indicators. Independent capabilities are not proof of maliciousness.
var Rules = []Rule{
	rule("RS001", "HIGH", "behavior", `(?i)(curl|wget)[^\n]*(\|\s*(ba)?sh|;\s*(ba)?sh)|(?:iwr|invoke-webrequest)[^\n]*\|\s*iex`, "Remote download piped into an interpreter", "Remote content could execute with user privileges", "Download separately, verify integrity, and review before execution"),
	rule("RS002", "MEDIUM", "credential-access", `(?i)(~/|HOME[^\n]{0,12}|homedir[^\n]{0,12})\.(ssh|aws|kube)|\.config/gcloud|169\.254\.169\.254`, "Sensitive credential location referenced", "Code may access developer or cloud credentials", "Review the access and restrict credentials available to this process"),
	rule("RS003", "MEDIUM", "behavior", `(?i)\beval\s*\(|\bexec\s*\(|new\s+Function\s*\(`, "Dynamic code evaluation", "Computed code may hide behavior from static review", "Replace dynamic evaluation with explicit operations"),
	rule("RS004", "MEDIUM", "obfuscation", `(?i)base64\s*(-d|--decode)|b64decode\s*\(|fromCharCode\s*\(|Buffer\.from\([^\n]*['"]base64['"]`, "Encoded payload decoding", "Encoding can conceal commands or data", "Inspect decoded content without executing it"),
	rule("RS005", "INFO", "process", `(?i)child_process|subprocess\.(run|Popen|call)|os\.system\s*\(|execSync\s*\(`, "Process execution capability", "Code may launch external commands", "Review arguments, inputs, and execution entry points"),
	rule("RS006", "INFO", "network", `(?i)https?://[a-z0-9][a-z0-9._:/?=&%+-]*`, "Network destination reference", "Referenced destinations may receive data or supply code", "Verify destination ownership and data handling"),
	rule("RS007", "HIGH", "infra", `(?i)privileged\s*:\s*true|/var/run/docker\.sock|hostPID\s*:\s*true|cap_add\s*:.*SYS_ADMIN`, "Privileged container configuration", "Container may gain extensive host access", "Remove privileged mode, host sockets, and unnecessary capabilities"),
	rule("RS008", "MEDIUM", "infra", `(?i)^\s*FROM\s+[^\s]+:latest\b|^\s*USER\s+(root|0)\s*$`, "Mutable base image or explicit root user", "Image behavior may change or run with excessive privilege", "Pin image digests and use an unprivileged user"),
	rule("RS009", "HIGH", "cicd", `(?i)pull_request_target|permissions\s*:\s*write-all|\$\{\{\s*github\.event\.(issue|pull_request|comment)[^}]*\}\}`, "Privileged workflow trigger, permissions, or untrusted interpolation", "Untrusted inputs may reach privileged automation", "Use minimal permissions and pass untrusted values via environment variables"),
	rule("RS010", "MEDIUM", "cicd", `(?i)uses:\s*[a-z0-9_.-]+/[a-z0-9_./-]+@[^\s]+`, "Action reference requires immutable pin review", "Mutable action references can change upstream", "Pin third-party actions to full commit SHAs"),
	rule("RS011", "HIGH", "agents", `(?i)ignore (all |previous |prior )*(instructions|rules)|disable (security|sandbox)|send[^\n]{0,60}(secrets|credentials)|"(command|autoApprove|dangerouslySkipPermissions)"\s*:`, "Agent instructions or tool execution configuration requires review", "Repository content may influence an agent or launch tools", "Review configurations before trusting the workspace; minimize tool permissions"),
	rule("RS012", "HIGH", "secret", `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b|"type"\s*:\s*"service_account"`, "Potential exposed credential (value redacted)", "Credentials may be exposed to repository readers", "Revoke and rotate exposed credentials; remove them from history"),
	rule("RS013", "HIGH", "persistence", `(?i)(crontab\s|LaunchAgents/|\.bashrc|\.zshrc|systemctl\s+enable)`, "Persistence-related resource or command", "Code may change future shell or service execution", "Review writes and require explicit user consent"),
}

// KnownRule validates built-in local suppression targets. OSV results are not suppressible here.
func KnownRule(id string) bool {
	for _, r := range Rules {
		if r.ID == id {
			return true
		}
	}
	return id == "RS100" || id == "RS101" || id == "RS200"
}
