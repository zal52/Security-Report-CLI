import pytest

from security_report.compare import compare_reports, severity_counts
from security_report.models import SEVERITIES, Finding, ScanReport


def item(id="a", severity="high", line=1):
    return Finding(id, "sample", "RULE", severity, "src/app.py", line, "Example")


def test_categories_and_moved_line():
    result = compare_reports(
        ScanReport([item(), item("removed")]), ScanReport([item(line=99), item("added")])
    )
    assert [f.id for f in result.new] == ["added"]
    assert [f.id for f in result.existing] == ["a"]
    assert result.existing[0].line == 99
    assert [f.id for f in result.resolved] == ["removed"]
    assert result.blocked


def test_empty():
    result = compare_reports(ScanReport([]), ScanReport([]))
    assert result.new == result.existing == result.resolved == []
    assert not result.blocked


@pytest.mark.parametrize("severity", SEVERITIES)
def test_severities(severity):
    result = compare_reports(ScanReport([]), ScanReport([item(severity=severity)]))
    assert result.blocked == (severity in ("critical", "high"))
    counts = severity_counts(result.new)
    assert counts[severity] == 1
    assert sum(counts.values()) == 1


def test_existing_high_does_not_block():
    assert not compare_reports(ScanReport([item()]), ScanReport([item()])).blocked


@pytest.mark.parametrize("before", SEVERITIES)
@pytest.mark.parametrize("after", SEVERITIES)
def test_severity_changes(before, after):
    result = compare_reports(
        ScanReport([item(severity=before)]), ScanReport([item(severity=after)])
    )
    increased = SEVERITIES.index(after) < SEVERITIES.index(before)
    assert bool(result.escalated) == increased
    assert result.blocked == (increased and after in ("high", "critical"))
    assert len(result.existing) == 1
    assert result.new == result.resolved == []
