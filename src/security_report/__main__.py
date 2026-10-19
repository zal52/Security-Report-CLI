"""Command-line entry point: python -m security_report."""

import argparse
import sys
from pathlib import Path

from security_report.compare import compare_reports
from security_report.parser import ReportError, load_report
from security_report.report import console_summary, markdown_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare normalized security reports")
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    # Prevent accidentally overwriting either input report.
    if args.output.resolve() in (args.baseline.resolve(), args.current.resolve()):
        print("Error: output must not overwrite an input report", file=sys.stderr)
        return 2
    try:
        baseline = load_report(args.baseline)
        current = load_report(args.current)
        comparison = compare_reports(baseline, current)
        duplicates = (baseline.duplicate_count, current.duplicate_count)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown_report(comparison, duplicates), encoding="utf-8")
    except (ReportError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(console_summary(comparison, duplicates))
    return 1 if comparison.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
