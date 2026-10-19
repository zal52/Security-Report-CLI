import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_cli(current, output, baseline=None):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "security_report",
            "--baseline",
            str(baseline or ROOT / "examples/baseline.json"),
            "--current",
            str(current),
            "--output",
            str(output),
        ],
        env=os.environ | {"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "filename,code", [("current.json", 0), ("current_blocked.json", 1), ("scan_failed.json", 2)]
)
def test_exit_codes(tmp_path, filename, code):
    output = tmp_path / "nested/report.md"
    result = run_cli(ROOT / "examples" / filename, output)
    assert result.returncode == code
    if code == 2:
        assert "incomplete scan" in result.stderr
        assert not output.exists()
    else:
        report = output.read_text(encoding="utf-8")
        assert "## New" in report and "## Existing" in report and "## Resolved" in report
        assert "Critical | High | Medium | Low" in report
        assert "Security report" in result.stdout


def test_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    result = run_cli(bad, tmp_path / "out.md")
    assert result.returncode == 2
    assert "cannot read JSON" in result.stderr


def test_output_cannot_overwrite_input(tmp_path):
    path = tmp_path / "input.json"
    path.write_text('{"scan_status":"completed","findings":[]}', encoding="utf-8")
    original = path.read_bytes()
    assert run_cli(path, path).returncode == 2
    assert path.read_bytes() == original


def test_output_error(tmp_path):
    directory = tmp_path / "directory"
    directory.mkdir()
    assert run_cli(ROOT / "examples/current.json", directory).returncode == 2


def test_severity_increase_blocks_and_is_reported(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    data = json.loads((ROOT / "examples/baseline.json").read_text(encoding="utf-8"))
    data["findings"][0]["severity"] = "medium"
    baseline.write_text(json.dumps(data), encoding="utf-8")
    data["findings"][0]["severity"] = "critical"
    current.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "report.md"
    result = run_cli(current, output, baseline)
    assert result.returncode == 1
    assert "medium -> critical" in result.stdout
    assert "| old-high | medium | critical |" in output.read_text(encoding="utf-8")
