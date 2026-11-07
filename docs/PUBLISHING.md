# Publish the project and releases

RepoSpect can be an open-source repository before it has packaged releases. Keep the current early-development status and coverage limits visible. The repository and a versioned release are separate deliverables.

## Intended repository

- Owner/name: `IAbuElRuzz/RepoSpect`
- Visibility: public
- Description: `Inspect before you execute. A local-first Go CLI for repository security, suspicious installation behavior, and evidence-backed execution traces.`
- Suggested topics: `security`, `supply-chain-security`, `static-analysis`, `golang`, `cli`, `devsecops`, `malware-analysis`, `github-actions`, `mcp-security`.
- Default branch: `main`
- License: Apache-2.0

## First push

Run from this directory in an environment with GitHub network access and working GitHub CLI authentication. Never paste access tokens into a terminal command recorded in shared logs.

```sh
gh auth login --hostname github.com --web
```

If local Git has not yet been initialized:

```sh
git init -b main
git add .
git commit -m "Initial RepoSpect implementation and open-source project setup"
```

Create and push the repository:

```sh
gh repo create IAbuElRuzz/RepoSpect --public --source=. --remote=origin --push \
  --description "Inspect before you execute. A local-first Go CLI for repository security, suspicious installation behavior, and evidence-backed execution traces."
```

If the repository already exists, inspect its contents and ownership before setting a remote and pushing. Never force-push over an existing project. Then add topics:

```sh
gh repo edit IAbuElRuzz/RepoSpect \
  --add-topic security --add-topic supply-chain-security \
  --add-topic static-analysis --add-topic golang --add-topic cli \
  --add-topic devsecops --add-topic malware-analysis \
  --add-topic github-actions --add-topic mcp-security
```

Inspect hosted CI, the rendered README and asset links. Enable private vulnerability reporting and establish a monitored process before advertising private security-reporting support. Branch protections should require the actual configured CI checks once those checks have run.

## Versioned releases

The current GoReleaser configuration creates **draft** releases with macOS/Linux/Windows amd64/arm64 archives and checksums. The hosted release workflow has not been validated yet. Code signing and release provenance signing are not configured.

Before a first tagged pre-release:

1. Update CHANGELOG.md and verify installation documentation.
2. Run unit/integration, race, vet, runtime platform and release configuration checks.
3. Validate a GoReleaser snapshot locally or in CI; inspect archives and checksums.
4. Review the threat model and current limitations; keep experimental features labeled.
5. Tag a reviewed commit with an appropriate pre-release version, then inspect the generated draft release before publishing it as a pre-release.
6. Add signing/provenance and verification instructions before making signed-release claims.

No tag or release is created merely by initializing or publishing this repository.
