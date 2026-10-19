"""Stable IDs, rather than source locations, determine finding identity."""

from security_report.models import SEVERITIES, Comparison, Finding, ScanReport


def compare_reports(baseline: ScanReport, current: ScanReport) -> Comparison:
    old = {finding.id: finding for finding in baseline.findings}
    now = {finding.id: finding for finding in current.findings}
    return Comparison(
        new=[now[key] for key in sorted(now.keys() - old.keys())],
        existing=[now[key] for key in sorted(now.keys() & old.keys())],
        resolved=[old[key] for key in sorted(old.keys() - now.keys())],
        escalated=[
            (old[key], now[key])
            for key in sorted(now.keys() & old.keys())
            if SEVERITIES.index(now[key].severity) < SEVERITIES.index(old[key].severity)
        ],
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(f.severity == severity for f in findings) for severity in SEVERITIES}
