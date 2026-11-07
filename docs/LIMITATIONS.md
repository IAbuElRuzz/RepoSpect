# Supported coverage and remaining work

This is an early implementation, not yet a validated production security verdict engine.

Implemented: bounded static local scans; anonymous GitHub HEAD snapshot acquisition; lexical behavior, secret, infrastructure, workflow and agent rules; npm lifecycle script graph; literal cross-file references; manifest dependency inventory; npm lockfile v2/v3 inventory; pinned requirements.txt inventory; direct Go require declarations; explicit OSV queries for exact versions; revision comparison; report exports; policy thresholds and reasoned suppression.

Not implemented: OCI image filesystem/layer analysis, Trivy/Syft/Zizmor/YARA adapters, ASTs, interprocedural dataflow, resolved dependency graphs, npm lockfile v1, pnpm/Yarn/Poetry/uv lock parsing, dependency confusion and typosquatting, provenance/signature/integrity verification, generic entropy-based secrets, Azure token detection, comprehensive Terraform/Helm/Kubernetes semantic parsing, binary malware inspection, AI explanation and persistent explain-by-ID. Unsupported image/explain commands fail explicitly. No actual attack, compromise, exfiltration or malware verdict is inferred from lexical matches alone.

Text matching includes comments, tests and strings. Process, eval, decoding, network and credential references can all be legitimate. Contextual review is required. Network references are INFO severity. Rules are examples of suspicious capabilities rather than comprehensive detection. No precision, recall or performance claims have been established on an independently labeled corpus.

Excluded directories, symlinks, binaries, malformed supported manifests, unsupported lockfiles, and resource limits mark the scan incomplete. Unsupported language semantics remain documented limits even when `complete` is true. That field means input coverage within the implemented pipeline, never absence of vulnerabilities. Dependency ranges remain inventory declarations; exact OSV version matches do not prove installation. Transitive inventory is only available where npm lockfiles provide it. Conditional Python requirements are inventoried without environment evaluation.

Limits: 20,000 files; 2 MiB per file; 100 MiB total; 40 directory levels; correlation only up to 500 text files and 10,000 file-reference edges. GitHub downloads are capped at 50 MiB compressed and 100 MiB expanded. Symlinks and special archive members are rejected. Git revisions with symlinks or submodules are rejected rather than partially trusted. No external tool is executed during local scans; diff invokes the installed Git binary with controlled environment and no checkout.

Future milestones: schema validation against SARIF/CycloneDX standards, dedicated language parsers, severity enrichment, more package ecosystems, OCI adapters, broader labeled regression fixtures, profiler-guided performance budgets, signed release provenance, and independent security review.
