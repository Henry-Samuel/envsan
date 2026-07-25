import os
from types import SimpleNamespace

from envsan.models import Finding, Severity
from envsan.policy import EnvironmentPolicy
from envsan.scanner import scan_environment


def test_common_secret_name_detected():
    policy = EnvironmentPolicy()
    env = {"PATH": "/bin", "DATABASE_URL": "postgres://localhost/db"}
    findings = scan_environment(env=env, exclude={"PATH"}, policy=policy)
    assert any(f.variable == "DATABASE_URL" for f in findings)


def test_long_random_value_flagged():
    policy = EnvironmentPolicy()
    env = {"PLACEHOLDER": "x" * 25}
    findings = scan_environment(env=env, policy=policy)
    assert any(f.variable == "PLACEHOLDER" and f.severity == Severity.MEDIUM for f in findings)


def test_empty_environment_returns_no_findings():
    findings = scan_environment(env={"PATH": "/bin"}, exclude={"PATH"})
    assert findings == []
