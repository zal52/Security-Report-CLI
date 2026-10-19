import json

import pytest

from security_report.parser import ReportError, load_report, parse_report


def finding(**changes):
    item = dict(
        id="a",
        scanner="sample",
        rule_id="RULE",
        severity="high",
        file="src/app.py",
        line=1,
        message="Fictional finding",
    )
    return item | changes


def test_duplicates():
    report = parse_report(dict(scan_status="completed", findings=[finding(), finding()]))
    assert len(report.findings) == 1
    assert report.duplicate_count == 1


def test_conflicting_duplicates():
    with pytest.raises(ReportError, match="conflicting duplicate"):
        parse_report(dict(scan_status="completed", findings=[finding(), finding(line=2)]))


@pytest.mark.parametrize("field", list(finding()))
def test_missing_fields(field):
    item = finding()
    del item[field]
    with pytest.raises(ReportError, match=field):
        parse_report(dict(scan_status="completed", findings=[item]))


@pytest.mark.parametrize(
    "data", [None, [], {}, {"scan_status": "pending"}, {"scan_status": "completed", "findings": {}}]
)
def test_invalid_structure(data):
    with pytest.raises(ReportError):
        parse_report(data)


@pytest.mark.parametrize(
    "changes",
    [
        {"line": True},
        {"line": 0},
        {"line": "1"},
        {"severity": "unknown"},
        {"id": " "},
        {"extra": "must not be lost"},
    ],
)
def test_invalid_finding(changes):
    with pytest.raises(ReportError):
        parse_report(dict(scan_status="completed", findings=[finding(**changes)]))


def test_failed_scan():
    with pytest.raises(ReportError, match="incomplete scan"):
        parse_report(dict(scan_status="failed", findings=[]))


def test_file_errors(tmp_path):
    path = tmp_path / "report.json"
    with pytest.raises(ReportError, match="cannot read JSON"):
        load_report(path)
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ReportError, match="cannot read JSON"):
        load_report(path)
    path.write_text(json.dumps(dict(scan_status="completed", findings=[])), encoding="utf-8")
    assert load_report(path).findings == []
