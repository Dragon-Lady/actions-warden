"""Static wfx-loot indicators. Never execute helpers or include their contents in reports."""

import json
import re

_CONFIG = re.compile(r"\bWF_(?:CALLBACK2?|CTOKEN|EXFIL_[A-Z_]+|PRIVATE)\b")
_STAGING = re.compile(r"\.wfx-|\bwfx-loot-|WFX-BEGIN|\bwfx-ci-")
_HELPER = r"(?:\./)?\.ci-[a-z0-9]{6}\.sh"
# Match only at lexical command starts supplied by _command_starts. Quoted
# filenames must close before a delimiter; operators inside a filename are data.
_HELPER_COMMAND = re.compile(
    r"[ \t]*(?:(?:sh|bash|dash)[ \t]+(?:-[a-zA-Z]+[ \t]+)*)?"
    r"(?P<quote>[\"']?)" + _HELPER + r"(?P=quote)(?=\s|[;&|)<>]|$)"
)
_C2 = re.compile(
    r"(?<![\w.])(?:194\.150\.166\.244|18\.143\.168\.96|"
    r"153\.75\.82\.159|45\.61\.182\.54)(?![\w.])"
)
_CALLBACK = re.compile(r"\bWF_CALLBACK2?\b|\b(?:c" + r"url|w" + r"get)\b")


def _command_starts(text):
    """Locate simple shell command starts without executing or expanding text.

    Quotes, escapes and comments suppress literal separators. Command
    substitutions introduce their own quote context, including inside double
    quotes. This is a bounded lexical check, not a general shell parser.
    """
    yield 0
    index = 0
    quote = ""
    word_start = True
    contexts = []
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if char == "\\" and index + 1 < len(text):
            following = text[index + 1]
            if not quote or following in '$`"\\\n':
                if following != "\n":
                    word_start = False
                index += 2
                continue
        if char == '"':
            quote = "" if quote else '"'
            word_start = False
            index += 1
            continue
        if char == "'" and not quote:
            quote = "'"
            word_start = False
            index += 1
            continue
        if char == "#" and not quote and word_start:
            newline = text.find("\n", index)
            if newline == -1:
                return
            index = newline
            continue
        if text.startswith("$(", index):
            contexts.append((quote, ")"))
            quote = ""
            word_start = True
            index += 2
            yield index
            continue
        if char == "`":
            if contexts and contexts[-1][1] == "`":
                quote, _ = contexts.pop()
                word_start = False
                index += 1
            else:
                contexts.append((quote, "`"))
                quote = ""
                word_start = True
                index += 1
                yield index
            continue
        if quote:
            index += 1
            continue
        if char == "(":
            contexts.append(("", ")"))
            word_start = True
            index += 1
            yield index
            continue
        if char == ")" and contexts and contexts[-1][1] == ")":
            quote, _ = contexts.pop()
            word_start = False
        elif text[index:index + 2] in (">&", "<&", ">|", "&>"):
            # These are redirection operators, not fresh commands at & or |.
            word_start = True
            index += 2
            continue
        elif char in ";&|\n":
            word_start = True
            yield index + 1
        else:
            word_start = char.isspace() or char in "<>"
        index += 1


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
        if any(_HELPER_COMMAND.match(command, start) for start in _command_starts(command)):
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
