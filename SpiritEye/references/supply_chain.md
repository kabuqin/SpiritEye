---
name: supply_chain
description: Supply-chain attack detection — dependency tampering, mutable CI/CD action tags, unverified third-party actions, lockfile drift, and unauthenticated build-time code fetch
---

# Supply Chain Security

Supply-chain attacks compromise software through its trusted building blocks — dependencies, CI/CD actions, base images, and install scripts — rather than the first-party source itself. Detection focuses on places where unverified, mutable, or attacker-influenced third-party code is executed with build-time or runtime trust.

## Where to Look

**Dependency Manifests & Lockfiles**
- npm `package.json` / `package-lock.json`, pip `requirements.txt` / `Pipfile.lock`, Maven `pom.xml`, Gradle, Go `go.mod` / `go.sum`, RubyGems `Gemfile.lock`
- Version ranges (`^`, `>=`, floating tags) vs pinned exact versions
- Known-vulnerable dependency versions (CVE) without an SCA gate
- Typo-squatting / name-confusable package imports; packages replaced via registry mirror tampering

**CI/CD Pipelines**
- GitHub Actions: mutable tags (e.g. `@v3`), actions from unverified third-party orgs, actions not pinned by commit SHA
- `pull_request_target` workflows that execute PR-controlled code with elevated secrets
- Self-hosted runners reused across untrusted repositories
- Workflow files writable by pull requests or low-privilege contributors

**Build & Release**
- Unpinned base images (`FROM node:latest`, `FROM ubuntu:latest`) in Dockerfiles
- Install scripts fetching remote content at build time (`curl ... | sh`, `npm install -g <tarball-url>`)
- Downloaded artifacts installed without checksum / signature verification
- Missing SBOM or provenance attestation for released artifacts

## Source -> Sink Pattern

- **Source**: dependency specifiers, action refs, base image tags, install script URLs, registry configuration
- **Sink**: execution of unverified code — `npm install` / `pip install` / `mvn dependency:resolve`, `actions/checkout` + `run`, `docker build`, `curl | sh`, dynamic module loading from remote hosts

## How to Detect

- Diff lockfile vs manifest: entries present in manifest but missing from lockfile (drift) allow non-reproducible installs
- Search for floating version specifiers (`>=`, `*`, `latest`, `@v\d+` mutable tags) on executable dependencies
- For every third-party GitHub Action, check: org of the action vs repo org; pinned by full commit SHA vs tag; workflow permissions (`permissions:` block) scope
- Trace install/build scripts that fetch URLs; verify scheme allowlist and checksum verification
- Check whether secrets are reachable from PR-triggered workflow paths (`pull_request_target`, `workflow_run`)

## Confirming a Finding

- Reachability: does the vulnerable dependency / action / base image actually execute in a shipped build, or is it dead config?
- Trust boundary: is the action/dependency from a third-party org, or the same org as the repo (in-org mutable tags are design choice, not a finding)?
- Version state: is the version pinned to an exact, CVE-checked value, or floating?
- Impact: what does the executed third-party code have access to — repo secrets, registry credentials, production deployment?

## False-Positive Guardrails

- **In-org CI/CD**: when a mutable action tag (e.g. `@v3`) belongs to an action in the same org as the repository, skip `supply_chain`; only report third-party org actions
- **Complete lockfiles**: manifests fully pinned in a committed, in-sync lockfile → dependency management best practice, not a finding
- **No known CVE + pinned version**: unfixed version ranges without a known vulnerable version are advisory-level, cap at `Low`
- **Developer-local tooling**: scripts only invoked by the operator locally, without network-exfil capability, are operator self-harm — skip
- **Overlap with `cve_patterns`**: if the same sink is already covered by a known-CVE pattern, do not double-report under `supply_chain`

## Remediation

- Pin exact versions in lockfiles; use commit SHA for third-party CI actions (or at minimum exact immutable tags with org verification)
- Add SCA/dependency scanning (Dependabot, OSV-Scanner, Trivy) with PR gate on known CVEs
- Verify downloaded artifacts via checksum / signature; avoid `curl | sh` build patterns; pin base images to digest
- Scope workflow `permissions:` to least privilege; restrict `pull_request_target` and self-hosted runner usage
- Generate and publish SBOM (SPDX/CycloneDX) with provenance for released artifacts
