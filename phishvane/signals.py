"""Shared data structures used across all detection modules.

A ``Signal`` is a single piece of evidence produced by a module. Every signal
carries a risk-point contribution and a human-readable explanation so the final
verdict is fully transparent ("why did PhishVane flag this URL?").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """How strongly a single signal indicates phishing."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Signal:
    """One weighted risk indicator emitted by a detection module."""

    code: str          # stable machine id, e.g. "lexical.ip_host"
    title: str         # short human-readable label
    detail: str        # explanation / concrete evidence
    points: int        # risk contribution (0-100 scale, always >= 0)
    category: str      # owning module, e.g. "Lexical"
    severity: Severity = Severity.LOW

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "title": self.title,
            "detail": self.detail,
            "points": self.points,
            "category": self.category,
            "severity": self.severity.value,
        }


@dataclass
class ModuleResult:
    """The full output of a single detection module for one URL."""

    module: str                                   # module display name
    signals: list[Signal] = field(default_factory=list)
    facts: dict = field(default_factory=dict)     # collected data (age, issuer...)
    status: str = "ok"                            # ok | skipped | error
    note: str = ""                                # reason for skipped/error

    @property
    def points(self) -> int:
        return sum(s.points for s in self.signals)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "status": self.status,
            "note": self.note,
            "points": self.points,
            "facts": self.facts,
            "signals": [s.to_dict() for s in self.signals],
        }
