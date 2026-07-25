from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

from envsan.models import Finding, Severity

PatternRule = Tuple[re.Pattern[str], Severity, str, str | None]


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_BUILTIN_RULES: List[PatternRule] = [
    (
        _compile(r"(secret|token|password|passwd|pwd|api_key|apikey|access_key|private_key)"),
        Severity.CRITICAL,
        "Variable name suggests a secret.",
        "Store secrets in a secrets manager or an injected secret store.",
    ),
    (
        _compile(r"(key|passwd|password|secret|private|token)"),
        Severity.HIGH,
        "Generic sensitive-looking name without transport hint.",
        "Confirm whether this value is sensitive; prefer a secrets manager.",
    ),
    (
        _compile(r"(host|hosts)"),
        Severity.LOW,
        "Host-looking variable may embed a URL.",
        "Prefer explicit scheme and host split instead of a combined value.",
    ),
]


class EnvironmentPolicy:
    def __init__(self, rules: Iterable[PatternRule] | None = None) -> None:
        self.rules: List[PatternRule] = list(rules) if rules is not None else list(_BUILTIN_RULES)

    def evaluate_name(self, name: str) -> Finding | None:
        for pattern, severity, message, recommendation in self.rules:
            if pattern.search(name):
                return Finding(
                    variable=name,
                    severity=severity,
                    message=message,
                    recommendation=recommendation,
                )
        return None
