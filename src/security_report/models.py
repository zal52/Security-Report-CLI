"""Small data structures shared by the parser and comparison."""

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class Finding:
    id: str
    scanner: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str


@dataclass
class ScanReport:
    findings: list[Finding]
    duplicate_count: int = 0


@dataclass
class Comparison:
    new: list[Finding]
    existing: list[Finding]
    resolved: list[Finding]
    escalated: list[tuple[Finding, Finding]] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return any(f.severity in ("high", "critical") for f in self.new) or any(
            current.severity in ("high", "critical") for _, current in self.escalated
        )
