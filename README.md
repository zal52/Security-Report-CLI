# Security Report CLI

[![CI](https://github.com/zal52/Security-Report-CLI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zal52/Security-Report-CLI/actions/workflows/ci.yml)

A small Python 3.12+ CLI that compares two normalized security reports using stable
finding IDs. It labels findings as new, existing, or resolved, counts each severity,
prints a console summary, and writes a Markdown report.

A baseline helps a team review newly introduced high/critical findings without
blocking every merge request on the same old findings. Severity increases to high
or critical also require review, including high to critical. Existing findings still
need ownership and remediation; a passing comparison does not prove code is safe.

## Install and run

From the repository directory:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m security_report --baseline examples/baseline.json --current examples/current.json --output reports/security-report.md
```

The application uses only the standard library. pytest and Ruff are development tools.

Try the blocking and failed-scan examples:

```bash
python -m security_report --baseline examples/baseline.json --current examples/current_blocked.json --output reports/blocked.md
python -m security_report --baseline examples/baseline.json --current examples/scan_failed.json --output reports/failed.md
```

## Input format

Both files must contain a JSON object with `scan_status` and `findings`:

```json
{
  "scan_status": "completed",
  "findings": [
    {
      "id": "sql-injection-user-controller",
      "scanner": "example-sast",
      "rule_id": "SQL_INJECTION",
      "severity": "high",
      "file": "src/users.py",
      "line": 42,
      "message": "Possible SQL injection"
    }
  ]
}
```

All finding fields shown are required. Text fields must be nonempty strings;
`line` must be a positive integer; severity is exactly `critical`, `high`, `medium`,
or `low`. Unknown finding fields are rejected to avoid discarding information.
IDs must be stable and globally unique across scanners in a report; adapters can
namespace IDs when necessary. A line change does not create a new finding.
Existing findings display current details; resolved findings display baseline details.

Exact duplicate findings are removed and their count appears in both outputs.
Conflicting entries with the same ID cause an error instead of silently choosing one.
`{"scan_status": "completed", "findings": []}` is a valid clean scan.
`scan_status: "failed"` means an incomplete scan, even if findings is empty.
Missing, unreadable, or malformed input also causes an error.
All sample findings are fictional and contain no credentials.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No new high/critical findings or severity increases to high/critical |
| 1 | New high/critical findings or severity increases to high/critical require review |
| 2 | Invalid input, incomplete scan, or output write error |

A comparison report is written for codes 0 and 1. Errors go to stderr. Invalid
inputs do not generate a comparison report; an existing output from a previous
run is not refreshed, so automation must check the exit code and use fresh outputs.

## Checks

```bash
ruff check .
pytest
```

Tests cover comparison categories, moved lines, all severities, empty reports,
duplicates, validation errors, scanner failure, output errors, and CLI exit codes.

## GitHub Actions

The [CI workflow](https://github.com/zal52/Security-Report-CLI/actions/workflows/ci.yml)
runs automatically on pushes and pull requests, and can also be started manually.
It installs the project on Python 3.12, runs Ruff and pytest, and compares the
passing fictional example reports. Tests include the expected blocking and failed
scan cases; those are successful tests when the CLI returns the expected exit codes.

The badge above shows the latest main-branch status. Open a workflow run to see
individual checks, verbose test results, and the generated security report in the
run summary. Test results (JUnit XML) and the Markdown report are saved as an artifact
for 14 days, including available files when a check fails. No secrets are required.

## GitLab CI

The repository is hosted on GitHub, but this configuration runs only in GitLab
(for example, after importing or mirroring the repository there). It does not
perform real security scans. GitHub uses the separate workflow described above.

`.gitlab-ci.yml` uses the official `python:3.12-slim` image. Merge request and
default-branch pipelines install the project, run Ruff and pytest, then compare
the passing example reports. The comparison job uploads `reports/security-report.md`
with `when: always`, including when a completed comparison exits 1. An invalid scan
may have no report to upload. No AWS credentials or paid services are needed.

This example uses checked-in samples, not live scanner output or automatic main
branch artifact retrieval. In a real pipeline, supply a trusted baseline from the
main branch and normalized current scan data. Missing scans must never be replaced
with empty completed reports.

## Code layout and limitations

- `models.py`: finding, report, and comparison data structures.
- `parser.py`: JSON loading, validation, and duplicate handling.
- `compare.py`: stable-ID comparison and severity counts.
- `report.py`: console and Markdown rendering.
- `__main__.py`: arguments, file output, and exit codes.

This is not a vulnerability scanner, exploit validator, or replacement for security
review. It does not run Snyk or GitLab Secret Detection; it only processes normalized
sample reports. Real scanner adapters can be added later. ID stability and report
completeness depend on the producer. Severity increases remain a subset of existing
findings and show both old and new severities. Increases to high or critical block;
low to medium does not. Unchanged severity and decreases do not block.
Resolved means absent from the current
completed report, not independently verified as fixed.
