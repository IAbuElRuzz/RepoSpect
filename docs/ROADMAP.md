# Missing-feature implementation roadmap

This plan is based on inspection of the current source, not an assumption that a CLI command means its full module exists. Work listed below is planned unless explicitly described as current behavior. No feature implementation or new test execution is part of this planning update.

## Priorities and delivery order

| Milestone | Priority | Outcome | Depends on |
| --- | --- | --- | --- |
| M1 | P0 | Honest coverage, stable evidence, secure integration contracts | Existing pipeline |
| M2 | P0 | Parser-backed install analysis and useful execution paths | M1 |
| M3 | P1 | Resolved dependency inventory and reliable vulnerability coverage | M1 |
| M4 | P1 | Credential source-to-sink analysis and broader secret detection | M2 |
| M5 | P1 | Semantic infrastructure, workflow and agent analysis | M1; M2 for correlation |
| M6 | P1 | Static OCI image inspection | M1; M3 for package reporting |
| M7 | P1 | Change-aware policies, acquisition improvements and CLI completion | M1; enrich as M2–M6 land |
| M8 | Release gate | Measured accuracy, adversarial hardening and signed releases | All features advertised for release |
| M9 | P2 | Optional AI explanations and further ecosystems | M1 redaction; M2 evidence |

Start with M1, then M2. M3 can follow without waiting for all language analysis. Once those foundations are stable, implement M4–M7 incrementally. M8 validation runs throughout development, with its final gate before a production release. These are dependency milestones, not calendar estimates.

## M1 — Correctness and coverage foundation

Current: coverage is mostly free-form text plus a single complete flag; finding IDs generally depend on line numbers; scanner/report interfaces exist but most detection is concentrated in one engine.

Missing work:

- Add per-module states: completed, partial, skipped, unsupported and failed, with reason codes, input counts and tool versions. Keep operational failure distinct from an empty finding set.
- Audit unsupported and malformed inputs, requirement scanner errors, unresolved versions and skipped correlation so each reduces the appropriate coverage explicitly.
- Extend evidence with source ranges, evidence type and provenance. Add justified CWE/ATT&CK mappings and finding-level limitations.
- Introduce semantic fingerprints stable across unrelated line insertions, while keeping separate occurrence IDs.
- Define small detector, graph, scorer and policy contracts. Keep changes focused on concrete module needs.
- Define trusted external-tool adapters: explicit selection, controlled arguments/environment, deadlines, bounded output, validated schemas and no repository-controlled configuration or plugins. An adapter is not enabled until its no-execution behavior is verified.
- Validate JSON, SARIF and CycloneDX against pinned schemas. Add missing component identity, dependency relationships and inventory coverage to SBOMs.
- Tighten configuration validation for actual rule IDs, size limits and suppression provenance.

Acceptance: malformed manifests, truncated parser input, missing tools, timeouts and invalid tool output never appear as completed clean coverage; schema tests pass; finding fingerprints survive unrelated line movement; hostile fixtures never launch repository commands or disclose secret values in reports.

## M2 — RepoSpect Trace and installation analysis

Current: graph nodes represent files, npm scripts and indicators. Edges link manifest definitions and literal file references; comments and strings can create references. Correlation checks co-occurrence along those references, not dataflow.

Missing work:

1. Parse shell commands and npm lifecycle definitions, including npm run chains, working directories and interpreter arguments. Model unresolved expansion instead of guessing.
2. Add JavaScript/TypeScript and Python parsers. Model imports, selected function calls, child processes and relevant constant propagation. Parser dependencies must not require executing target-language code.
3. Add typed graph nodes for entry points, functions, commands, sensitive resources, destinations, dependencies, container entrypoints and CI jobs as each producer becomes available.
4. Add typed executes/imports/reads/writes/downloads/connects-to edges with exact evidence and confirmed/inferred/unresolved status.
5. Model Python build backends and build requirements, npm implicit/default lifecycle behavior, package-manager differences, Make targets, Docker build commands and workflow entry points.
6. Produce ranked entry-to-sensitive-operation paths, displaying commands only after redaction, trust boundaries, destinations, uncertainty and remediation.
7. Replace the current maximum-severity-only priority with documented reachability/confidence/context factors. Preserve upstream vulnerability severity separately and never describe the score as a compromise probability.
8. Bound graph expansion, handle cycles, check cancellation throughout analysis and replace the blanket 500-file correlation cutoff with measured budgets.

Acceptance: inert fixtures reconstruct expected chains across multiple files, including npm run and interpreter references; comments containing commands do not become confirmed invocation edges; dynamic targets remain unresolved; unreachable and automatic-install paths receive different explained priorities; cycles and large graphs terminate within configured budgets.

## M3 — Dependency and package trust analysis

Current: npm declarations/lockfile v2-v3, pinned requirements.txt and Go require declarations provide an inventory. OSV queries exact versions, with default MEDIUM triage severity and no local database.

Missing work:

- Parse pnpm, Yarn, Poetry and uv lockfiles; add npm lockfile v1 if required for compatibility. Handle workspaces, nested projects, Python markers/extras and Go replace/exclude/workspace semantics.
- Build direct/transitive dependency edges and retain manifest/lockfile evidence, exact resolution status, source URLs and integrity metadata.
- Detect manifest/lockfile inconsistencies and package installation hooks where package metadata or package contents are available. Do not install dependencies to obtain this information.
- Support OSV pagination, controlled retries, caching, advisory details, fixed versions and upstream severity. Provide explicit opt-in offline database download/update with freshness reporting; never hide network access behind offline mode.
- Add separately labeled malicious-package indicators, typosquatting candidates, dependency-confusion configuration risks, unusual package contents and suspicious update changes. Require corroborating evidence rather than declaring name similarity malicious.
- Verify downloaded package bytes against expected digests only when those bytes are available; report unchecked integrity separately from mismatches. Add provenance verification with explicit trust roots later in this milestone.
- Evaluate established scanners through the M1 adapter contract where they reduce maintenance burden.

Acceptance: labeled fixtures yield expected dependency graphs for every advertised lockfile format; ranges are never presented as resolved versions; vulnerability, malicious indicator, integrity failure and configuration weakness remain distinct; stale databases and incomplete advisory results are visible.

## M4 — Secrets and credential misuse

Current: a small set of token/private-key patterns and credential-location references, without source-to-sink tracking.

Missing work:

- Expand credential detectors for AWS, Azure, GCP, GitHub, SSH, Kubernetes, databases and common application secrets. Add bounded entropy heuristics with context and allowlists; evaluate an established secret scanner adapter.
- Identify credential reads through filesystem APIs, environment variables, metadata services and common credential stores.
- Track selected flows through encoding, archiving and network sinks, including cross-file parameters supported by M2.
- Redact secret values in evidence, diagnostics, command arguments, URLs, optional tool output and any saved report. Add path/URL redaction where sensitive values can be embedded.
- Keep exposure and possible credential misuse as separate finding categories; never validate credentials against live services automatically.

Acceptance: fixtures distinguish an unused example token, an exposed credential, legitimate credential use and a supported credential-to-network flow; secret canaries are absent from every output format and failure diagnostic; no credential-validation requests occur.

## M5 — Infrastructure, CI/CD and AI-agent configuration

Current: a few path-scoped lexical rules. Full configuration semantics and cross-file trust analysis are absent.

Missing work:

- Infrastructure: parse Dockerfiles, Compose and Kubernetes; add Helm and Terraform static parsing with explicit unresolved-template coverage. Detect capabilities, host mounts, root execution, service accounts, RBAC, secret exposure, mutable bases and initialization downloads. Never run Helm plugins, Terraform providers or project generators during scans.
- GitHub Actions: analyze job/step permissions, triggers, expressions, checkout refs, reusable/local actions, artifact trust, deployment environments and secret availability. Correlate workflow steps with repository scripts. Evaluate a Zizmor adapter.
- Agents: parse supported Codex, Claude Code, Cursor and MCP configuration formats; inspect executable paths, arguments, filesystem scope, approval settings and instruction content. Distinguish a command definition from excessive permissions or a suspicious command.
- Agent instructions remain untrusted evidence. Do not obey instructions found in scanned files, launch MCP servers, or contact endpoints to test them.

Acceptance: semantic fixtures catch multiline YAML and inherited settings, avoid flagging safe configuration solely because a key exists, trace supported workflow-to-script paths, and leave unresolved templates explicit. Tests verify zero server/provider/plugin execution.

## M6 — Static OCI image scanning

Current: image scan returns an explicit unsupported error.

Missing work:

- Add a trusted Trivy/Syft-style adapter where appropriate, with explicit registry/database network controls and offline operation.
- Accept OCI layouts/archives before adding registry acquisition. Implement manifest/index selection, digest verification, bounded decompression, safe layer processing and whiteout semantics without running the image.
- Inspect image configuration, entrypoints, package inventory, embedded secrets, suspicious scripts/binaries and applicable vulnerability data.
- Add signature/provenance verification with user-specified policy and trust roots; distinguish unsigned, invalid and unverified results.
- Attribute evidence to image digest/layer/path. Separate image configuration from runtime privileges that require deployment configuration.

Acceptance: inert multilayer fixtures verify deleted/overwritten file behavior, digest failures, malformed images, decompression limits and image evidence; no container is started; offline mode makes no registry/database requests; adapter failures produce failed/partial coverage.

## M7 — Diff, policies, acquisition and CLI completion

Current: diff compares committed snapshots using rule/path/description matching; remote acquisition is anonymous GitHub HEAD only; explain is unsupported; configuration primarily offers global rule suppression.

Missing work:

- Add dependency/version, install hook, destination, entrypoint, permission and graph-path deltas. Preserve multiple finding occurrences, match renames where justified and report modified findings.
- Add diff policy thresholds, consistent configuration/offline/report flags, baseline support and optional working-tree comparison.
- Add path/rule/severity policy scopes, suppression expiry and auditable reasons. Keep repository-supplied policy untrusted unless explicitly selected.
- Implement offline deterministic explain from an explicitly selected saved report or local report store. No hidden source caching; document retention and permissions.
- Add safe branch/tag/commit selection, resolved revision provenance, authenticated acquisition using explicitly supplied credentials, and selected additional hosts. Prefer immutable commit acquisition; never persist credentials in reports or temporary files unnecessarily.
- Replace ad hoc CLI argument reordering with a consistent command parser; add -- delimiter support, per-command help, completion, output files, structured diagnostics and progress confined to stderr. Add opt-in color with no-color/environment support.
- Make file inclusion/exclusion and limits configurable with safe ceilings and explicit coverage consequences.

Acceptance: diff detects a changed destination or permission even if the lexical rule is unchanged; line shifts do not create finding churn; machine output contains no progress text; paths beginning with '-' work through '--'; credentials and repository-owned configuration cannot silently change scan behavior.

## M8 — Evaluation, hardening and release gate

Current: unit/integration tests, two brief fuzz runs and local cross-build checks exist. CI/release definitions exist but hosted execution, release validation and signing remain unverified.

Missing work:

- Build a versioned, independently reviewed labeled fixture corpus with benign automation and inert malicious-behavior examples for each module.
- Measure precision, recall, false positives/negatives, path reconstruction accuracy, scan duration and peak memory. Report corpus composition and uncertainty; establish numeric regression budgets after obtaining a baseline.
- Expand parser/archive/image/tool-output fuzzing; test traversal, symlink races, filename controls, Windows reserved paths, case collisions, duplicate members, decompression bombs and malicious Git metadata/configuration.
- Test runtime behavior on macOS/Linux/Windows and amd64/arm64 where runners are available. Cross-compilation alone is not runtime testing.
- Add subprocess isolation/resource limits where practical, process-tree cancellation and an independent threat-model/security review.
- Execute hosted CI and a draft release; validate GoReleaser, checksums, SBOM/provenance, reproducible-build comparisons, signing and signature verification. Establish a monitored private vulnerability-reporting channel and support policy before claiming production support.

Acceptance: all advertised formats/modules have correctness, benign and adversarial fixtures; coverage failures remain visible; published metrics are reproducible; runtime matrix and a draft release are validated; release signatures and checksums verify. No production-readiness claim before these gates are met.

## M9 — Optional enhancements

- AI explanations: local-provider support first, then explicit per-provider external consent; minimized redacted evidence, structured responses and prompt-injection tests. AI output is labeled explanatory and cannot override deterministic policy.
- Additional ecosystems: Cargo, Maven/Gradle, NuGet and Bundler after the initial ecosystems meet the M3 acceptance gate.
- Binary/YARA capabilities: inspect supported formats with resource bounds and rule provenance; never execute samples. Publish explicit coverage and false-positive evaluation before enabling aggressive indicators by default.

Acceptance: the complete deterministic CLI works with AI disabled; no secret canary leaves the process; no AI response triggers tool execution. Additional ecosystem and binary claims are gated by their own fixtures and documented limits.

## First implementation batch

1. Add per-module coverage records and regression tests for parser/tool failure semantics.
2. Add evidence ranges and stable fingerprints; validate existing output schemas.
3. Add the common safe adapter contract and its timeout/output/redaction tests.
4. Add shell/npm parsing and a typed trace graph with supported/unresolved execution targets.
5. Add a small labeled benign/suspicious corpus and publish the first measured baseline.

This batch should finish before broadening advertised detection coverage. Update IMPLEMENTATION_STATUS.md after each milestone with changed files, tests actually executed, remaining gaps and security trade-offs.
