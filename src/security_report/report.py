"""Human-readable console and Markdown output."""

import html

from security_report.compare import severity_counts
from security_report.models import SEVERITIES, Comparison


def result_text(comparison: Comparison) -> str:
    return "Review required" if comparison.blocked else "Passed"


def console_summary(comparison: Comparison, duplicates: tuple[int, int]) -> str:
    lines = ["Security report"]
    for name in ("new", "existing", "resolved"):
        lines.append(f"{name.title() + ':':10} {len(getattr(comparison, name))}")
    lines.append(f"Duplicates removed: baseline={duplicates[0]}, current={duplicates[1]}")
    lines.append(f"Severity increased (subset of existing): {len(comparison.escalated)}")
    for name in ("new", "existing", "resolved"):
        counts = severity_counts(getattr(comparison, name))
        lines.append(
            f"{name.title()} severity: " + ", ".join(f"{s}={n}" for s, n in counts.items())
        )
    lines.append("")
    for finding in comparison.new:
        lines.append(
            f"{finding.severity.upper():8} {finding.message} - {finding.file}:{finding.line}"
        )
    for previous, current in comparison.escalated:
        lines.append(
            f"ESCALATED {current.id}: {previous.severity} -> {current.severity}"
            f" - {current.file}:{current.line}"
        )
    lines.append(f"\nResult: {result_text(comparison)}")
    return "\n".join(lines)


def escape_cell(value: str) -> str:
    return html.escape(value).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def markdown_report(comparison: Comparison, duplicates: tuple[int, int]) -> str:
    lines = [
        "# Security report",
        "",
        f"Result: **{result_text(comparison)}**",
        "",
        f"Exact duplicates removed: baseline={duplicates[0]}, current={duplicates[1]}.",
        "",
        "| Category | Total | Critical | High | Medium | Low |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in ("new", "existing", "resolved"):
        findings = getattr(comparison, name)
        counts = severity_counts(findings)
        values = " | ".join(str(counts[s]) for s in SEVERITIES)
        lines.append(f"| {name.title()} | {len(findings)} | {values} |")
    for name in ("new", "existing", "resolved"):
        lines.extend(["", f"## {name.title()}", ""])
        findings = getattr(comparison, name)
        if not findings:
            lines.append("None.")
            continue
        lines.extend(
            [
                "| ID | Scanner | Rule | Severity | Location | Message |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings:
            cells = [
                finding.id,
                finding.scanner,
                finding.rule_id,
                finding.severity,
                f"{finding.file}:{finding.line}",
                finding.message,
            ]
            lines.append("| " + " | ".join(escape_cell(cell) for cell in cells) + " |")
    lines.extend(["", "## Severity increases", "", "Subset of existing findings.", ""])
    if not comparison.escalated:
        lines.append("None.")
    else:
        lines.extend(["| ID | Previous severity | Current severity |", "| --- | --- | --- |"])
        for previous, current in comparison.escalated:
            lines.append(
                f"| {escape_cell(current.id)} | {previous.severity} | {current.severity} |"
            )
    return "\n".join(lines) + "\n"
