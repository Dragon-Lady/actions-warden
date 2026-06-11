"""Core scanning logic for GitHub Actions workflow auditing.

This scanner is intentionally text/regex based rather than YAML-parsed: a
hostile workflow can be crafted to parse oddly, and we want to inspect what is
actually written on disk, not what a parser normalizes. It runs read-only, makes
no network calls, and executes nothing.

Rules map to the GitHub Actions security-hardening guidance and to the
post-compromise TTP seen in 2026 (stolen PAT -> injected workflow that exfils
secrets or runs attacker code). A finding means "review this workflow," not
"this repo is compromised."
"""

import os
import re
from datetime import datetime, timezone

DEFAULT_MAX_FILE_BYTES = 1 * 1024 * 1024

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".pytest_cache",
}

# Attacker-controllable expression contexts. Interpolating these into an inline
# shell `run:` step is GitHub's top-documented Actions injection vector.
_UNTRUSTED_EXPR = r"github\.(?:head_ref|event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|comment\.body|review\.body|review_comment\.body|pages|head_commit\.message|commits)|event\.pull_request\.head\.repo\.full_name)"

# Outbound-exfil command families. Built from parts so the repo does not ship a
# single copy-paste-ready exfil one-liner.
_OUTBOUND = r"(?:" + "|".join(
    [
        r"c" + r"url",
        r"w" + r"get",
        r"\bnc\b",
        r"ncat",
        r"invoke-?webrequest",
        r"invoke-?restmethod",
        r"\birm\b",
        r"\biwr\b",
    ]
) + r")"

_PIPE_SHELL = (
    r"(?:c" + r"url|w" + r"get)\b[^\n|]*\|\s*(?:bash|sh|zsh)\b"
    r"|(?:i" + r"wr|invoke-?webrequest|i" + r"rm|invoke-?restmethod)\b[^\n|]*\|\s*"
    r"(?:iex|invoke-?expression)\b"
)


RULES = [
    {
        "id": "secret-exfiltration",
        "severity": "critical",
        "type": "workflow-secret-exfiltration",
        "description": (
            "Workflow references a secret and an outbound network command; a "
            "secret may be sent off the runner."
        ),
        "file_all": [r"secrets\.", _OUTBOUND],
    },
    {
        "id": "untrusted-input-injection",
        "severity": "high",
        "type": "workflow-script-injection",
        "description": (
            "Attacker-controllable input is interpolated into the workflow; in "
            "an inline run step this allows shell script injection."
        ),
        "line_any": [r"\$\{\{[^}]*" + _UNTRUSTED_EXPR],
    },
    {
        "id": "remote-code-in-run",
        "severity": "high",
        "type": "workflow-remote-code-exec",
        "description": "Workflow pipes a downloaded script directly into a shell.",
        "line_any": [_PIPE_SHELL],
    },
    {
        "id": "pull-request-target-head-checkout",
        "severity": "high",
        "type": "workflow-pwn-request",
        "description": (
            "pull_request_target runs with repo secrets while checking out "
            "pull-request-controlled code (the 'pwn request' pattern)."
        ),
        "file_all": [
            r"pull_request_target",
            r"uses:\s*actions/checkout",
            r"ref:\s*\$\{\{[^}]*github\.event\.pull_request\.head|head\.ref|head\.sha",
        ],
    },
    {
        "id": "self-hosted-on-untrusted",
        "severity": "medium",
        "type": "workflow-self-hosted-untrusted",
        "description": (
            "A self-hosted runner is used in a workflow triggered by external "
            "pull requests; untrusted code may run on your hardware."
        ),
        "file_all": [r"runs-on:\s*\[?[^\n]*self-hosted", r"on:[^\n]*pull_request\b|pull_request:"],
    },
    {
        "id": "permissions-write-all",
        "severity": "medium",
        "type": "workflow-broad-permissions",
        "description": "Workflow grants write-all token permissions (broad blast radius).",
        "line_any": [r"permissions:\s*write-all"],
    },
    {
        "id": "oidc-with-write",
        "severity": "medium",
        "type": "workflow-oidc-write",
        "description": (
            "Workflow combines OIDC id-token issuance with write permissions; "
            "confirm this scope is intended."
        ),
        "file_all": [r"id-token:\s*write", r"contents:\s*write"],
    },
    {
        "id": "unpinned-action",
        "severity": "low",
        "type": "workflow-unpinned-action",
        "description": (
            "Third-party action is pinned to a mutable tag/branch, not a full "
            "commit SHA; a hijacked tag would run in your pipeline."
        ),
        "uses_unpinned": True,
    },
]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"uses:\s*([^\s@'\"]+)@([^\s'\"#]+)")


def scan_target(target_path=".", max_file_bytes=DEFAULT_MAX_FILE_BYTES):
    from . import __version__

    root = os.path.abspath(target_path or ".")
    findings = []
    files_scanned = 0
    files_skipped = 0

    for file_path in _iter_workflow_files(root):
        size = _safe_size(file_path)
        if size is None:
            continue
        if size > max_file_bytes:
            files_skipped += 1
            findings.append(
                _finding("low", "large-file-skipped", file_path,
                         f"Skipped file over {max_file_bytes} bytes.")
            )
            continue
        text = _read_text(file_path)
        if text is None:
            findings.append(
                _finding("low", "read-error", file_path,
                         "Could not read file as UTF-8 text.")
            )
            continue
        files_scanned += 1
        scan_workflow_text(file_path, text, findings)

    deduped = _dedupe_findings(findings)
    risk = _risk_level(deduped)
    return {
        "tool": "actions-warden",
        "version": __version__,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "target": root,
        "risk": risk,
        "summary": {
            "filesScanned": files_scanned,
            "filesSkipped": files_skipped,
            "findings": len(deduped),
        },
        "findings": deduped,
        "guidance": _guidance_for_risk(risk),
    }


def scan_workflow_text(file_path, text, findings):
    lines = text.splitlines()
    for rule in RULES:
        if rule.get("uses_unpinned"):
            _scan_unpinned(rule, file_path, lines, findings)
        elif "line_any" in rule:
            hit = _match_line_any(rule["line_any"], lines)
            if hit:
                line_no, snippet = hit
                findings.append(
                    _finding(rule["severity"], rule["type"], file_path,
                             f"{rule['description']} Rule: {rule['id']}.",
                             _defang(snippet), line_no)
                )
        elif "file_all" in rule:
            evidence = _match_file_all(rule["file_all"], text)
            if evidence is not None:
                findings.append(
                    _finding(rule["severity"], rule["type"], file_path,
                             f"{rule['description']} Rule: {rule['id']}.",
                             evidence)
                )


def _match_line_any(patterns, lines):
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for index, line in enumerate(lines):
        for pattern in compiled:
            match = pattern.search(line)
            if match:
                return index + 1, line.strip()
    return None


def _match_file_all(patterns, text):
    snippets = []
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            return None
        snippets.append(_defang(match.group(0).strip()))
    return " + ".join(snippets)


def _scan_unpinned(rule, file_path, lines, findings):
    for index, line in enumerate(lines):
        match = _USES_RE.search(line)
        if not match:
            continue
        ref_path, ref = match.group(1), match.group(2)
        if ref_path.startswith("./") or ref_path.startswith("docker://"):
            continue
        if "/" not in ref_path:
            continue
        if _SHA_RE.match(ref):
            continue
        findings.append(
            _finding(rule["severity"], rule["type"], file_path,
                     f"{rule['description']} Rule: {rule['id']}.",
                     _defang(f"uses: {ref_path}@{ref}"), index + 1)
        )


def _iter_workflow_files(root):
    if os.path.isfile(root):
        if _looks_like_workflow_path(root) or root.lower().endswith((".yml", ".yaml")):
            yield root
        return

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS:
                        stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False) and _looks_like_workflow_path(entry.path):
                    yield entry.path
            except OSError:
                continue


def _looks_like_workflow_path(path):
    norm = path.replace("\\", "/")
    base = os.path.basename(norm).lower()
    if base in ("action.yml", "action.yaml"):
        return True
    if "/.github/workflows/" in norm and base.endswith((".yml", ".yaml")):
        return True
    return False


def _safe_size(file_path):
    try:
        return os.stat(file_path).st_size
    except OSError:
        return None


def _read_text(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def _defang(text):
    text = str(text)
    text = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), text, flags=re.IGNORECASE)
    if len(text) > 140:
        text = text[:137] + "..."
    return text


def _finding(severity, type_, path, message, evidence="", line=None):
    return {
        "severity": severity,
        "type": type_,
        "path": path,
        "line": line,
        "message": message,
        "evidence": evidence,
    }


def _dedupe_findings(findings):
    seen = set()
    result = []
    for item in findings:
        key = (item["severity"], item["type"], item["path"], item["line"],
               item["message"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _risk_level(findings):
    if any(item["severity"] in ("critical", "high") for item in findings):
        return "blocked"
    if any(item["severity"] in ("medium", "low") for item in findings):
        return "review-needed"
    return "no-known-indicators"


def _guidance_for_risk(risk):
    if risk == "blocked":
        return [
            "Do not merge or re-enable these workflows until each finding is explained.",
            "If a workflow was added or changed unexpectedly, treat it as possible token-theft tampering and rotate affected PATs/secrets.",
            "Pin third-party actions to full commit SHAs and scope GITHUB_TOKEN permissions to least privilege.",
            "Never interpolate attacker-controllable input directly into run steps; pass it through an intermediate env var.",
        ]
    if risk == "review-needed":
        return [
            "Review medium/low findings before trusting this pipeline.",
            "Pin actions to commit SHAs and confirm self-hosted-runner and permission scopes are intended.",
        ]
    return [
        "No blocking workflow risks were found by this scanner.",
        "This is a narrow CI/CD config scanner, not proof the pipeline is safe.",
    ]
