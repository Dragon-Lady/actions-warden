"""Static wfx-loot indicators. Never execute helpers or include their contents in reports."""

import json
import re

_CONFIG = re.compile(r"\bWF_(?:CALLBACK2?|CTOKEN|EXFIL_[A-Z_]+|PRIVATE)\b")
_STAGING = re.compile(r"\.wfx-|\bwfx-loot-|WFX-BEGIN|\bwfx-ci-")
_HELPER = r"(?:\./)?\.ci-[a-z0-9]{6}\.sh"
# Command positions only: an echo, description, or unrelated dependency name is
# not evidence of an install hook. This is not a general shell parser.
_HELPER_COMMAND = re.compile(
    r"(?:^|[;&|\n]|\$\()\s*(?:(?:sh|bash|dash)\s+(?:-[a-zA-Z]+\s+)*)?"
    r"[\"']?" + _HELPER + r"[\"']?(?=\s|[;&|)]|$)"
)
_C2 = re.compile(
    r"(?<![\w.])(?:194\.150\.166\.244|18\.143\.168\.96|"
    r"153\.75\.82\.159|45\.61\.182\.54)(?![\w.])"
)
_CALLBACK = re.compile(r"\bWF_CALLBACK2?\b|\b(?:c" + r"url|w" + r"get)\b")


def _finding(path, kind, message, severity="high"):
    return {
        "severity": severity,
        "type": kind,
        "path": path,
        "line": None,
        "message": message,
        "evidence": "Structural indicators only; source text omitted.",
    }


def scan_wfx_text(path, text):
    """Match combinations of campaign markers in workflows or shell scripts."""
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    found = []
    config = set(_CONFIG.findall(active))
    if len(config) >= 2 or (config and _STAGING.search(active)):
        found.append(_finding(
            path, "wfx-payload-markers",
            "Combined wfx-loot payload markers found. Do not run this file until "
            "reviewed. Static content does not establish execution or theft.", "critical",
        ))
    if _C2.search(active) and _CALLBACK.search(active):
        found.append(_finding(
            path, "wfx-callback-indicator",
            "A reported wfx-loot address appears with a callback or network command. "
            "Review the file and its history; this does not prove a connection occurred.",
        ))
    return found


def scan_package_scripts(path, text):
    """Inspect scripts only; invalid package metadata must remain incomplete."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package metadata is not an object")
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict) or any(not isinstance(v, str) for v in scripts.values()):
        raise ValueError("package scripts are not strings")
    found = []
    for command in scripts.values():
        if _HELPER_COMMAND.search(command):
            found.append(_finding(
                path, "wfx-npm-hidden-helper",
                "An npm script invokes a hidden shell helper with the wfx-loot "
                "filename pattern. Inspect it before installing or building. "
                "The filename pattern alone is not proof of compromise.",
            ))
        found.extend(scan_wfx_text(path, command))
    return found


GUIDANCE = [
    "wfx-loot review: preserve evidence and inspect PRs, branches, commits and "
    "Actions history, including reverted changes. A current-file scan cannot "
    "clear earlier activity; a missing run alone does not prove execution.",
    "If the payload ran, treat every credential accessible to that job or "
    "developer process as exposed. From a trusted environment, revoke the "
    "attacker's account access and rotate affected credentials; review AWS "
    "trust policies/new keys and Azure federated identities for persistence.",
    "This scanner is read-only. It does not fetch history, inspect cloud "
    "accounts, block network traffic, or remove persistence.",
]
