"""Read-only auditor for risky or injected GitHub Actions workflow config."""

__version__ = "0.1.0"

from .scanner import RULES, scan_target, scan_workflow_text

__all__ = ["RULES", "scan_target", "scan_workflow_text", "__version__"]
