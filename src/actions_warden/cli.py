"""Command-line interface.

Argument parsing is hand-rolled (not argparse) to preserve the exit-code
contract: argparse exits with code 2 on a bad flag, but 2 means "blocking
workflow risk found" here. Usage/runtime errors must exit 1.
"""

import json
import os
import sys

from . import __version__
from .scanner import scan_target

HELP_TEXT = f"""actions-warden {__version__}

Read-only auditor for risky or injected GitHub Actions workflow config.

Usage:
  actions-warden [target] [--json] [--report report.json]
  actions-warden --version

Options:
  --json              print JSON report to stdout
  --report <path>     create a new private JSON report; existing paths refused
  --version           print package version and exit
  -h, --help          show this help

Exit codes:
  0  no blocking workflow risks found
  1  usage/runtime error or incomplete scan
  2  blocking workflow risks found
"""


def _parse_args(argv):
    args = {
        "target": ".",
        "json": False,
        "report_path": "",
        "help": False,
        "version": False,
    }
    target_seen = False
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--help", "-h"):
            args["help"] = True
        elif arg in ("--version", "-V"):
            args["version"] = True
        elif arg == "--json":
            args["json"] = True
        elif arg == "--report":
            index += 1
            if index >= len(argv) or not argv[index] or argv[index].startswith("-"):
                raise ValueError("--report requires a file path")
            args["report_path"] = argv[index]
        elif arg.startswith("--report="):
            args["report_path"] = arg[len("--report="):]
            if not args["report_path"]:
                raise ValueError("--report requires a file path")
        elif not arg.startswith("-"):
            if target_seen:
                raise ValueError("Only one target path may be specified")
            args["target"] = arg
            target_seen = True
        else:
            raise ValueError(f"Unknown argument: {arg}")
        index += 1
    return args


def _print_human(report, written_report_path):
    print("Actions Warden")
    print(f"Target: {report['target']}")
    print(f"Risk: {report['risk']}")
    print(f"Scanned: {report['summary']['filesScanned']} workflow files")
    print(f"Findings: {report['summary']['findings']}")
    if not report["coverage"]["complete"]:
        print("INCOMPLETE: some inputs could not be inspected; this is not a passed scan.")
        for error in report["coverage"]["errors"]:
            print(f"  {error['reason']}: {error['path']}")
    print("")

    if report["risk"] == "blocked":
        print("STOP")
        print("Risky or injected GitHub Actions workflow config was found.")
        print("Review each finding before merging, re-enabling, or trusting this pipeline.")
        print("")
    else:
        print("No blocking workflow risks were found by this scanner.")
        print("This does not prove the pipeline is safe; it only covers known local rules.")
        print("")

    if report["findings"]:
        print("Findings:")
        for item in report["findings"]:
            location = item["path"]
            if item.get("line"):
                location = f"{location}:{item['line']}"
            print(f"[{item['severity']}] {item['type']}")
            print(f"  {location}")
            print(f"  {item['message']}")
            if item["evidence"]:
                print(f"  evidence: {item['evidence']}")
        print("")

    print("Guidance:")
    for item in report["guidance"]:
        print(f"- {item}")

    if written_report_path:
        print("")
        print(f"JSON report written: {written_report_path}")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = _parse_args(argv)
        if args["help"]:
            print(HELP_TEXT)
            return 0
        if args["version"]:
            print(__version__)
            return 0

        report = scan_target(args["target"])
        written_report_path = ""
        if args["report_path"]:
            written_report_path = os.path.abspath(args["report_path"])
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(written_report_path, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(report, indent=2) + "\n")

        if args["json"]:
            print(json.dumps(report, indent=2))
        else:
            _print_human(report, written_report_path)

        if report["risk"] == "blocked":
            return 2
        return 0 if report["coverage"]["complete"] else 1
    except (ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
