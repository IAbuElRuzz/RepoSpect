# Implementation status

## Local scan and trace milestone

Changed: cmd/repospect, pkg/findings, internal/scanner, internal/reporting, rules, testdata/suspicious.

Implemented bounded discovery, 13 lexical rules, npm/Python install entry point detection, deterministic findings, reasoned suppression, severity policy, redaction, static execution-reference graphs and lifecycle/credential/network correlation. Exports: text, JSON, SARIF, CycloneDX inventory, Mermaid and DOT.

Validated with scanner regression tests, CLI policy/error tests and report serialization tests. The harmless 3-file fixture produces 7 findings and a manifest → lifecycle script → JavaScript file → shell file reference chain. All inferred edges are labeled; strings and comments are deliberately analyzed and can produce indicators.

Limitations: no general AST, dataflow or binary analysis. Read docs/LIMITATIONS.md. Security: no project execution or source transmission; confinement and resource limits are enforced.

## Acquisition, dependencies and revisions milestone

Changed: internal/acquisition, internal/dependencies, internal/revision, internal/scanner/inventory.go, CLI flags and commands.

Implemented bounded anonymous GitHub HEAD archive acquisition, dependency inventory for npm declarations/lockfile v2-v3, pinned Python requirements and Go require declarations, explicit OSV package/version lookup, and committed-revision comparison using Git archives.

Validated with hostile ZIP path/link tests, URL validation, injected HTTP transport tests for OSV success/malformed/pagination responses, and a temporary Git repository integration test for introduced findings. Live GitHub/OSV requests are unverified in this environment: shell DNS resolution is unavailable. Unsupported lockfiles and snapshot links fail or reduce coverage explicitly.

## Release foundation milestone

Changed: README.md, LICENSE, SECURITY.md, CONTRIBUTING.md, Makefile, docs, .github/workflows and .goreleaser.yaml.

Added cross-platform CI configuration, pinned action references, draft release automation, checksums, threat model, hardening guidance, scoring methodology and roadmap. Signing is not configured. Hosted workflows and GoReleaser configuration have not been executed here.

Local validation: go test ./... and go test -race ./... passed across all six tested packages; go vet ./... passed. Native macOS build and Linux/Windows amd64 cross-builds passed. Cross-builds do not establish runtime compatibility. A 3-second command-reference fuzz run passed with 72,541 executions. A 3-second archive-extraction fuzz run passed with 5,653 executions; neither brief fuzz run establishes parser safety. No precision/recall or production performance claims are made.

## Next milestone

Add established OCI and specialized scanner integrations with explicit failure/coverage semantics; validate output schemas; replace lexical references with language-aware call/dataflow analysis; expand package ecosystems and labeled false-positive regressions; validate release workflows and add signing/provenance. image scan and persistent explain remain explicit unsupported commands, not implemented modules.
