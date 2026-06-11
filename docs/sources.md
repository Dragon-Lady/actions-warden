# Sources

Detection rules are derived from public, defensive guidance and from the
behaviour described in 2026 GitHub repository-theft reporting:

- GitHub: Security hardening for GitHub Actions
  https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- Script-injection guidance (untrusted input in run steps), pinning actions to
  full commit SHAs, least-privilege `GITHUB_TOKEN`, and `pull_request_target`
  risks are all documented in that guide.
- Post-compromise workflow-injection behaviour (stolen PAT -> mass clone ->
  malicious workflow) is described in vendor analyses of the May 2026 GitHub
  internal-repository breach (tracked as TeamPCP / UNC6780) and related CI/CD
  malware writeups.

This project stores no malware payloads, no raw exfiltration one-liners, and no
secrets. Command-family markers are assembled from parts at runtime so the
repository does not ship copy-paste-ready attack strings.
