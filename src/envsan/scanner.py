from __future__ import annotations

import os
from typing import Dict, Iterable, List

from envsan.models import Finding, Severity
from envsan.policy import EnvironmentPolicy

_DEFAULT_EXCLUDE = {"PATH", "PWD", "OLDPWD", "HOME", "USER", "SHELL", "TERM"}


def _looks_like_value_secret(value: str) -> bool:
    if len(value) >= 20:
        return True
    return False


def scan_environment(
    env: Dict[str, str] | None = None,
    *,
    exclude: Iterable[str] | None = None,
    policy: EnvironmentPolicy | None = None,
) -> List[Finding]:
    if env is None:
        env = dict(os.environ)

    policy = policy or EnvironmentPolicy()
    excluded = set(exclude or _DEFAULT_EXCLUDE)
    findings: List[Finding] = []

    for name, value in env.items():
        if name in excluded:
            continue

        name_finding = policy.evaluate_name(name)
        if name_finding:
            findings.append(name_finding)

        if _looks_like_value_secret(value):
            findings.append(
                Finding(
                    variable=name,
                    severity=Severity.MEDIUM,
                    message="Value is unusually long for a normal config string.",
                    recommendation="Rotate the value if it is sensitive and review exposure surface.",
                )
            )

    findings.sort(key=lambda f: (f.severity.value, f.variable))
    return findings
