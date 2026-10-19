"""Validate reports before any comparison is attempted."""

import json
from pathlib import Path

from security_report.models import SEVERITIES, Finding, ScanReport


class ReportError(ValueError):
    """Invalid input or incomplete scanner execution."""


def load_report(path: Path) -> ScanReport:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReportError(f"{path}: cannot read JSON: {exc}") from exc
    try:
        return parse_report(data)
    except ReportError as exc:
        raise ReportError(f"{path}: {exc}") from exc


def parse_report(data: object) -> ScanReport:
    if not isinstance(data, dict):
        raise ReportError("report must be a JSON object")
    if data.get("scan_status") == "failed":
        raise ReportError("incomplete scan: scan_status is failed")
    if data.get("scan_status") != "completed":
        raise ReportError("scan_status must be completed or failed")
    if not isinstance(data.get("findings"), list):
        raise ReportError("findings must be an array")

    unique: dict[str, Finding] = {}
    duplicates = 0
    for index, item in enumerate(data["findings"]):
        finding = parse_finding(item, index)
        previous = unique.get(finding.id)
        if previous is not None:
            if previous != finding:
                raise ReportError(f"conflicting duplicate ID {finding.id!r}; no data discarded")
            duplicates += 1
        else:
            unique[finding.id] = finding
    return ScanReport(list(unique.values()), duplicates)


def parse_finding(item: object, index: int) -> Finding:
    prefix = f"findings[{index}]"
    if not isinstance(item, dict):
        raise ReportError(f"{prefix} must be an object")
    for field in ("id", "scanner", "rule_id", "severity", "file", "message"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            raise ReportError(f"{prefix}.{field} must be a nonempty string")
    if item["severity"] not in SEVERITIES:
        raise ReportError(f"{prefix}.severity must be one of {', '.join(SEVERITIES)}")
    if type(item.get("line")) is not int or item["line"] < 1:
        raise ReportError(f"{prefix}.line must be a positive integer")
    # Unknown fields are rejected so duplicate checks cannot discard extra information.
    fields = {"id", "scanner", "rule_id", "severity", "file", "line", "message"}
    if item.keys() - fields:
        raise ReportError(f"{prefix}: unknown fields: {', '.join(sorted(item.keys() - fields))}")
    return Finding(**item)
