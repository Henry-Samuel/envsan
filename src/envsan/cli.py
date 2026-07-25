from __future__ import annotations

import json
import os
import sys
from typing import List

from envsan.models import Finding, Severity
from envsan.policy import EnvironmentPolicy
from envsan.scanner import scan_environment


def _render(finding: Finding) -> str:
    prefix = {
        Severity.CRITICAL: "[!]",
        Severity.HIGH: "[!]",
        Severity.MEDIUM: "[~]",
        Severity.LOW: "[i]",
    }[finding.severity]
    lines = [f"{prefix} {finding.severity.value.upper()}: {finding.variable} — {finding.message}"]
    if finding.recommendation:
        lines.append(f"       recommendation: {finding.recommendation}")
    return "\n".join(lines)


def run(argv: List[str]) -> int:
    as_json = "--json" in argv
    policy = EnvironmentPolicy()
    findings = scan_environment(env=dict(os.environ), policy=policy)

    if not findings:
        if as_json:
            print(json.dumps({"findings": []}))
        else:
            print("envsan: no findings.")
        return 0

    if as_json:
        payload = {
            "findings": [
                {
                    "variable": f.variable,
                    "severity": f.severity.value,
                    "message": f.message,
                    "recommendation": f.recommendation,
                }
                for f in findings
            ]
        }
        print(json.dumps(payload))
    else:
        print(f"envsan: {len(findings)} finding(s).\n")
        print("\n".join(_render(f) for f in findings))

    return 0 if all(f.severity in {Severity.LOW} for f in findings) else 1


def main() -> int:
    return run(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
