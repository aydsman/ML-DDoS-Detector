from datetime import datetime, timezone

import pytest

from ddos_detector.firewall_contract import BlockRequest, FirewallResult, RuleState


@pytest.mark.parametrize("source", ["::1", "10.10.10.30; echo bad", "not-an-ip"])
def test_request_rejects_non_ipv4_source(source):
    with pytest.raises(ValueError):
        BlockRequest("block-1", source, "Manual lab test")


@pytest.mark.parametrize("duration", [0, -1, True, float("nan"), float("inf")])
def test_request_rejects_invalid_duration(duration):
    with pytest.raises(ValueError):
        BlockRequest("block-1", "10.10.10.30", "Manual lab test", duration)


def test_timeout_can_preserve_unknown_installation():
    result = FirewallResult("block-1", "apply", False, RuleState.UNKNOWN,
                            datetime.now(timezone.utc), "Command timed out")
    assert result.rule_state == RuleState.UNKNOWN


@pytest.mark.parametrize("operation,state", [
    ("apply", RuleState.ABSENT),
    ("remove", RuleState.INSTALLED),
    ("expire", RuleState.INSTALLED),
    ("verify", RuleState.UNKNOWN),
])
def test_success_requires_verified_operation_state(operation, state):
    with pytest.raises(ValueError):
        FirewallResult("block-1", operation, True, state, datetime.now(timezone.utc))


def test_verify_can_confirm_rule_absent():
    result = FirewallResult("block-1", "verify", True, RuleState.ABSENT,
                            datetime.now(timezone.utc))
    assert result.success
