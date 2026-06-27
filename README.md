# Actions Warden

Read-only auditor for risky or injected GitHub Actions workflow config.

After the 2026 wave of repository-theft attacks, a common post-compromise move
is: steal a token, then inject or tamper with a repo's `.github/workflows/` so
CI exfiltrates secrets or runs attacker code. Actions Warden scans those workflow
files for the patterns that enable it.

It does not execute workflows, contact GitHub, modify files, or prove a pipeline
is safe.

## Install

```sh
pipx install actions-warden
# or
pip install actions-warden
```

Python 3.9+. No runtime dependencies.

## Usage

```sh
actions-warden /path/to/repo
actions-warden /path/to/repo --json
actions-warden /path/to/repo --report report.json
```

It scans `.github/workflows/*.yml|*.yaml` and composite `action.yml|action.yaml`
files. You can also point it at a single workflow file.

Exit codes:

- `0`: no blocking workflow risks found
- `1`: usage or runtime error
- `2`: blocking workflow risks found (suitable as a CI gate)

## What It Flags

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `secret-exfiltration` | critical | a secret reference alongside an outbound network command |
| `untrusted-input-injection` | high | attacker-controllable `github.event.*` / `head_ref` interpolated into the workflow (shell injection in run steps) |
| `remote-code-in-run` | high | a downloaded script piped straight into a shell |
| `pull-request-target-head-checkout` | high | `pull_request_target` running with secrets while checking out PR-controlled code ("pwn request") |
| `checkout-unsafe-pr-opt-out` | high | `actions/checkout` explicitly setting `allow-unsafe-pr-checkout` on privileged PR-adjacent triggers |
| `self-hosted-on-untrusted` | medium | self-hosted runner reachable by external pull requests |
| `permissions-write-all` | medium | `write-all` token permissions |
| `oidc-with-write` | medium | OIDC `id-token: write` combined with `contents: write` |
| `deployment-trigger-review` | medium | workflows triggered by `deployment` / `deployment_status` that need GitHub workflow execution protections reviewed |
| `deployment-trigger-privileged` | high | deployment-triggered workflows that also reference secrets, OIDC, or write permissions |
| `unpinned-action` | low | third-party action pinned to a mutable tag/branch instead of a commit SHA |

The rules are conservative. A finding means "review this workflow," not "this
repo is compromised."

GitHub announced safer `actions/checkout@v7` defaults for common
`pull_request_target` pwn-request patterns on 2026-06-18, with supported major
tag backports planned for 2026-07-16. Workflows pinned to a minor, patch, or
full SHA need an explicit upgrade to receive that behavior, and any
`allow-unsafe-pr-checkout` opt-out should be treated as a deliberate high-risk
review item.

GitHub's workflow execution protections public preview also lets organizations
restrict which actors and event types can trigger workflows. Treat
`deployment` / `deployment_status` workflows as review items, and treat
deployment-triggered workflows that use secrets, OIDC, or write permissions as
blocked until the repository or organization restricts that trigger.

## Why text-based, not YAML-parsed

A hostile workflow can be written to parse in surprising ways. Actions Warden
inspects what is actually on disk rather than a parser's normalized view, and
stays dependency-free. The tradeoff is coarser context: some `file_all` rules
flag co-occurrence within a file rather than within a single job.

## Scope Limits

This is a narrow CI/CD config scanner. It does not scan dependencies or packages
(see a dependency/supply-chain scanner for that), does not resolve reusable or
remote workflows, and will not catch every possible injection or obfuscated
payload.
