from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    variable: str
    severity: Severity
    message: str
    recommendation: str | None = None
