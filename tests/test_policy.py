import re

import pytest

from envsan.models import Finding, Severity
from envsan.policy import EnvironmentPolicy


def test_explicit_rule_matches_sensitive_variable():
    rule = (re.compile("secret", re.IGNORECASE), Severity.CRITICAL, "bad", "fix")
    finding = EnvironmentPolicy(rules=[rule]).evaluate_name("MY_SECRET")
    assert finding == Finding(variable="MY_SECRET", severity=Severity.CRITICAL, message="bad", recommendation="fix")


def test_password_name_maps_to_critical_severity():
    policy = EnvironmentPolicy(rules=[
        (re.compile(r"(secret|token|password|passwd|pwd|api_key|apikey|access_key|private_key)", re.IGNORECASE), Severity.CRITICAL, "secret", "fix"),
    ])
    finding = policy.evaluate_name("Password")
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.variable == "Password"


def test_non_matching_name_returns_none():
    policy = EnvironmentPolicy(rules=[(re.compile("zzz"), Severity.LOW, "m", None)])
    assert policy.evaluate_name("LOG_LEVEL") is None
