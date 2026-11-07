# Threat model

RepoSpect inspects attacker-controlled source, filenames, manifests and configuration. The attacker may attempt resource exhaustion, symlink traversal, terminal injection, disclosure through diagnostics, or misleading analysis. Static indicators do not prove compromise.

The default scan performs no network requests and executes no project code. Traversal skips symlinks, .git, vendor, node_modules and virtual environments. File count, depth, per-file bytes and aggregate bytes are bounded. Skipped input is reported as incomplete coverage. Files are checked before and after opening; scans should target a stable snapshot because concurrent filesystem mutation remains a risk. Binary files are not semantically analyzed.

Output evidence contains rule descriptions rather than source excerpts, preventing credential values from appearing in findings. Paths and graph labels are sanitized for terminal controls. JSON and graph encoders escape syntax. No credential validation or AI transmission occurs.

External integrations are opt-in and must never silently report success after tool failure. Parsing vulnerabilities in Go, Git or external tools remain upstream risks. Scanning cannot establish runtime behavior, exploitability, package authenticity, or the absence of malware. No sandboxed execution is implemented.

Local file reads use Go's os.Root confinement, in addition to same-file checks, to prevent symlink escape during concurrent mutation. Directory enumeration can still observe a changing tree; use an immutable snapshot for reproducible results. Traversal entries are bounded as well as successful file reads. Output graph identifiers are opaque hashes to prevent filename control characters from corrupting graph identity. Machine-readable evidence preserves paths using JSON escaping; terminal paths are sanitized.
