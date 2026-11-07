# Architecture and confidence

The Go CLI dispatches to a bounded discovery and rule engine. `pkg/findings` defines versioned output, evidence and graph structures. `internal/scanner` inspects text, manifests and literal references. `internal/acquisition` retrieves anonymous GitHub ZIP snapshots. `internal/revision` scans Git archive snapshots. `internal/dependencies` implements opt-in OSV batch queries. `internal/reporting` renders text, JSON, SARIF, CycloneDX inventory, Mermaid and DOT.

The engine exposes a context-aware Scanner interface; reporters have a writer interface. Rules use Go RE2 regular expressions and deterministic manifest parsing. Rule definitions currently live in `internal/scanner/rules.go`; external executable rule plugins are deliberately unsupported.

Graph nodes currently cover files, npm scripts and indicators. A manifest defining a script is confirmed static evidence. A literal path token referencing another file is inferred: strings and comments can generate these edges. The graph does not resolve imports, calls, shell variables, aliases, functions or runtime conditions. Every edge has a location and description. An install hook reaching files with credential and network indicators produces RS200, explicitly without claiming dataflow or exfiltration.

Finding IDs hash rule, path and location (and some manifest descriptions). They are deterministic for unchanged input, but line insertion can change IDs. Revision matching ignores line shifts and matches rule, path and description. Renames are treated as removal/addition. Only the first match of each lexical rule per file is reported to bound output. This is not a complete occurrence inventory.

Risk priority is the maximum severity rank multiplied by 20: INFO=0, LOW=20, MEDIUM=40, HIGH=60, CRITICAL=80. It is not a compromise probability. RS200 raises priority through a HIGH finding; weak indicator counts do not accumulate. OSV findings have MEDIUM triage severity because this implementation does not fetch upstream CVSS details.

Suppression is explicit JSON mapping of rule IDs to nonempty review reasons. The CLI reports that suppression was applied. Suppressions affect local rule output and correlation inputs, but not OSV results. Deterministic security decisions do not use AI.
