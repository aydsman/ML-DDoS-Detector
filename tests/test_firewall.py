from datetime import datetime, timedelta, timezone

import pytest

from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_contract import BlockRequest, RuleState


class FakeFirewall:
    def __init__(self):
        self.state = RuleState.ABSENT
        self.applied = []
        self.apply_error = None
        self.verify_error = None
        self.removed = []
        self.remove_error = None

    def apply(self, request, scope):
        self.applied.append((request, scope))
        if self.apply_error:
            raise self.apply_error
        self.state = RuleState.INSTALLED

    def verify(self, request, scope):
        if self.verify_error:
            raise self.verify_error
        return self.state

    def remove(self, request, scope):
        self.removed.append((request, scope))
        if self.remove_error:
            raise self.remove_error
        self.state = RuleState.ABSENT


@pytest.fixture
def scope():
    return FirewallScope("enp0s8", "10.10.10.10", ("10.0.2.0/24",), verified=True)


@pytest.fixture
def request_record():
    return BlockRequest("block-1", "10.10.10.30", "Explicit lab request")


def test_apply_verifies_rule_and_does_not_renew_on_retry(scope, request_record):
    firewall = FakeFirewall()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, scope, clock=lambda: now)
    result = adapter.apply(request_record)
    assert result.success and result.rule_state == RuleState.INSTALLED
    original, = adapter.confirmed_blocks
    assert original.expires_at == now + timedelta(seconds=300)
    now += timedelta(seconds=20)
    assert adapter.apply(request_record).success
    assert adapter.confirmed_blocks == (original,)
    assert firewall.applied == [(request_record, scope)]
    assert adapter.reserved_count == 1
    assert len(adapter.audit_events) == 2


def test_apply_error_with_verified_absence_releases_capacity(scope, request_record):
    firewall = FakeFirewall()
    firewall.apply_error = PermissionError("Permission denied")
    adapter = FirewallAdapter(firewall, scope)
    result = adapter.apply(request_record)
    assert not result.success and result.rule_state == RuleState.ABSENT
    assert "PermissionError" in result.error
    assert adapter.reserved_count == 0


def test_timeout_retains_capacity_until_reconciliation(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope, max_blocks=1)

    def timeout_after_possible_install(request, scope):
        firewall.applied.append((request, scope))
        firewall.verify_error = TimeoutError("Verification unavailable")
        raise TimeoutError("Apply outcome uncertain")

    firewall.apply = timeout_after_possible_install
    result = adapter.apply(request_record)
    assert not result.success and result.rule_state == RuleState.UNKNOWN
    assert adapter.reserved_count == 1
    assert adapter.confirmed_blocks == ()
    with pytest.raises(ValueError, match="capacity"):
        adapter.apply(BlockRequest("block-2", "10.10.10.31", "Second request"))
    assert adapter.apply(request_record).rule_state == RuleState.UNKNOWN
    assert len(firewall.applied) == 1
    firewall.verify_error = None
    assert adapter.verify(request_record).rule_state == RuleState.ABSENT
    assert adapter.reserved_count == 0


@pytest.mark.parametrize("source", ["10.10.10.10", "10.10.10.20", "127.0.0.2", "10.0.2.2"])
def test_protected_sources_rejected_before_transport(scope, source):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    with pytest.raises(ValueError, match="protected or allowlisted"):
        adapter.apply(BlockRequest("block-1", source, "Manual test"))
    assert firewall.applied == []
    assert adapter.reserved_count == 0


def test_unverified_scope_rejects_requests(request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, FirewallScope("enp0s8", "10.10.10.10", ()))
    with pytest.raises(ValueError, match="must be verified"):
        adapter.apply(request_record)
    assert firewall.applied == []


def test_different_id_for_same_source_cannot_install_twice(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    adapter.apply(request_record)
    with pytest.raises(ValueError, match="already has"):
        adapter.apply(BlockRequest("block-2", request_record.source_ip, "Repeated detection"))
    assert len(firewall.applied) == 1


def test_reused_id_for_different_source_rejected(scope, request_record):
    adapter = FirewallAdapter(FakeFirewall(), scope)
    adapter.apply(request_record)
    with pytest.raises(ValueError, match="different request"):
        adapter.apply(BlockRequest(request_record.block_id, "10.10.10.31", "Other source"))


def test_command_return_without_installation_is_not_success(scope, request_record):
    firewall = FakeFirewall()
    firewall.apply = lambda request, scope: None
    adapter = FirewallAdapter(firewall, scope)
    result = adapter.apply(request_record)
    assert not result.success
    assert result.rule_state == RuleState.ABSENT
    assert adapter.confirmed_blocks == ()
    assert adapter.reserved_count == 0


def test_concurrent_retries_install_once(scope, request_record):
    from concurrent.futures import ThreadPoolExecutor

    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(adapter.apply, [request_record] * 8))
    assert all(result.success for result in results)
    assert len(firewall.applied) == 1
    assert adapter.reserved_count == 1


def test_expiry_removes_at_deadline_and_releases_slot(scope, request_record):
    firewall = FakeFirewall()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, scope, clock=lambda: now)
    adapter.apply(request_record)
    now += timedelta(seconds=299)
    assert adapter.expire_due() == ()
    assert firewall.removed == []
    now += timedelta(seconds=1)
    result, = adapter.expire_due()
    assert result.operation == "expire"
    assert result.success and result.rule_state == RuleState.ABSENT
    assert firewall.removed == [(request_record, scope)]
    assert adapter.reserved_count == 0
    assert adapter.confirmed_blocks == ()
    assert adapter.expire_due() == ()


def test_failed_expiry_keeps_original_deadline_and_retries(scope, request_record):
    firewall = FakeFirewall()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, scope, clock=lambda: now)
    adapter.apply(request_record)
    original, = adapter.confirmed_blocks
    firewall.remove_error = PermissionError("Denied")
    now += timedelta(seconds=300)
    result, = adapter.expire_due()
    assert not result.success and result.rule_state == RuleState.INSTALLED
    assert "PermissionError" in result.error
    assert adapter.reserved_count == 1
    assert adapter.confirmed_blocks == (original,)
    firewall.remove_error = None
    now += timedelta(seconds=5)
    result, = adapter.expire_due()
    assert result.success
    assert adapter.reserved_count == 0


def test_removal_timeout_keeps_slot_until_verified_reconciliation(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope, max_blocks=1)
    adapter.apply(request_record)
    original, = adapter.confirmed_blocks

    def uncertain_remove(request, scope):
        firewall.state = RuleState.ABSENT
        firewall.verify_error = TimeoutError("No verification response")
        raise TimeoutError("Removal outcome uncertain")

    firewall.remove = uncertain_remove
    result = adapter.remove(request_record)
    assert not result.success and result.rule_state == RuleState.UNKNOWN
    assert adapter.reserved_count == 1
    assert adapter.confirmed_blocks == (original,)
    with pytest.raises(ValueError, match="capacity"):
        adapter.apply(BlockRequest("block-2", "10.10.10.31", "Other source"))
    firewall.verify_error = None
    assert adapter.verify(request_record).rule_state == RuleState.ABSENT
    assert adapter.reserved_count == 0
    assert adapter.confirmed_blocks == ()


def test_manual_remove_is_idempotent_and_same_action_cannot_restart(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    adapter.apply(request_record)
    result = adapter.remove(request_record)
    assert result.success
    assert adapter.remove(request_record) == result
    assert len(firewall.removed) == 1
    with pytest.raises(ValueError, match="new block ID"):
        adapter.apply(request_record)
    adapter.apply(BlockRequest("block-2", request_record.source_ip, "New action"))
    assert adapter.reserved_count == 1


def test_expiry_accepts_rule_already_absent(scope, request_record):
    firewall = FakeFirewall()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, scope, clock=lambda: now)
    adapter.apply(request_record)
    firewall.state = RuleState.ABSENT
    now += timedelta(seconds=300)
    result, = adapter.expire_due()
    assert result.success
    assert firewall.removed == []
    assert adapter.reserved_count == 0


def test_successful_remove_command_requires_absence_verification(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    adapter.apply(request_record)
    firewall.remove = lambda request, scope: None
    result = adapter.remove(request_record)
    assert not result.success and result.rule_state == RuleState.INSTALLED
    assert adapter.reserved_count == 1


def test_remove_cannot_target_an_untracked_action(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    with pytest.raises(ValueError, match="existing reserved request"):
        adapter.remove(request_record)
    assert firewall.removed == []


def test_apply_retry_observing_absence_reports_failed_installation(scope, request_record):
    firewall = FakeFirewall()
    firewall.state = RuleState.UNKNOWN
    adapter = FirewallAdapter(firewall, scope)
    assert adapter.apply(request_record).rule_state == RuleState.UNKNOWN

    firewall.state = RuleState.ABSENT
    result = adapter.apply(request_record)
    assert result.operation == "apply"
    assert result.rule_state == RuleState.ABSENT
    assert not result.success
    assert firewall.applied == []
    assert adapter.reserved_count == 0


def test_poll_confirms_and_expires_uncertain_installation(scope, request_record):
    firewall = FakeFirewall()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, scope, clock=lambda: now)

    def apply_with_uncertain_result(request, scope):
        firewall.state = RuleState.UNKNOWN

    firewall.apply = apply_with_uncertain_result
    assert adapter.apply(request_record).rule_state == RuleState.UNKNOWN
    assert adapter.expire_due() == ()

    now += timedelta(seconds=20)
    firewall.state = RuleState.INSTALLED
    assert adapter.expire_due() == ()
    confirmed, = adapter.confirmed_blocks
    assert confirmed.blocked_at == now

    now += timedelta(seconds=request_record.duration_seconds)
    expired, = adapter.expire_due()
    assert expired.success and expired.rule_state == RuleState.ABSENT
    assert adapter.reserved_count == 0


@pytest.mark.parametrize("source", [168430090, b"\x0a\x0a\x0a\x0a"])
def test_request_rejects_non_string_ipv4_aliases(source):
    with pytest.raises(ValueError, match="IPv4 string"):
        BlockRequest("block-1", source, "Explicit request")


@pytest.mark.parametrize("duration", [1e-12, -1e100, 1e100, 10**400])
def test_request_rejects_unrepresentable_duration(duration):
    with pytest.raises(ValueError, match="representable"):
        BlockRequest("block-1", "10.10.10.30", "Explicit request", duration)


def test_confirmed_action_cannot_restart_after_verifying_absence(scope, request_record):
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, scope)
    assert adapter.apply(request_record).success
    firewall.state = RuleState.ABSENT

    assert adapter.verify(request_record).rule_state == RuleState.ABSENT
    assert adapter.reserved_count == 0
    result = adapter.remove(request_record)
    assert result.operation == "remove" and result.success
    with pytest.raises(ValueError, match="new block ID"):
        adapter.apply(request_record)
    assert len(firewall.applied) == 1
