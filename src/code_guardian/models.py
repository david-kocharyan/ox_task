"""Domain models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_trivy(cls, value: str | None) -> Severity:
        if not value:
            return cls.UNKNOWN
        upper = value.upper()
        try:
            return cls(upper)
        except ValueError:
            return cls.UNKNOWN


@dataclass(frozen=True)
class Popularity:
    stars: int | None = None
    forks: int | None = None
    source: str = "github"

    @property
    def display(self) -> str:
        if self.stars is None and self.forks is None:
            return "n/a"
        stars = self.stars if self.stars is not None else "?"
        forks = self.forks if self.forks is not None else "?"
        return f"★ {stars} / forks {forks}"


@dataclass(frozen=True)
class Vulnerability:
    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None
    severity: Severity
    title: str
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.vulnerability_id,
            "package": self.pkg_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity.value,
            "title": self.title,
            "target": self.target,
        }


@dataclass
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0

    def increment(self, severity: Severity) -> None:
        match severity:
            case Severity.CRITICAL:
                self.critical += 1
            case Severity.HIGH:
                self.high += 1
            case Severity.MEDIUM:
                self.medium += 1
            case Severity.LOW:
                self.low += 1
            case _:
                self.unknown += 1

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.unknown

    def to_dict(self) -> dict[str, int]:
        return {
            "CRITICAL": self.critical,
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "LOW": self.low,
            "UNKNOWN": self.unknown,
            "TOTAL": self.total,
        }


@dataclass
class DependencyEdge:
    parent: str
    child: str


@dataclass
class ScanResult:
    repository: str
    repository_name: str
    popularity: Popularity
    severity_counts: SeverityCounts
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "repository_name": self.repository_name,
            "popularity": {
                "stars": self.popularity.stars,
                "forks": self.popularity.forks,
                "source": self.popularity.source,
            },
            "severity_counts": self.severity_counts.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "dependencies": [
                {"parent": e.parent, "child": e.child} for e in self.dependencies
            ],
            "error": self.error,
        }
