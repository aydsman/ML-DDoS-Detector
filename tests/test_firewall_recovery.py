from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_contract import BlockRequest, RuleState
from ddos_detector.firewall_state import FirewallState
from test_firewall import FakeFirewall


def settings():
    return FirewallScope("enp0s8", "10.10.10.10", ("10.0.2.0/24",), True)


def test_restart_preserves_first_confirmation_deadline_and_audit(tmp_path):
    path = tmp_path / "state.sqlite"
    firewall = FakeFirewall()
    request = BlockRequest("a", "10.10.10.30", "Manual test")
    now = datetime(2026, 11, 14, tzinfo=timezone.utc)
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), clock=lambda: now, state_store=store)
        adapter.apply(request)
        first, = adapter.confirmed_blocks
        assert len(store.events()) == 1
    now += timedelta(seconds=200)
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), clock=lambda: now, state_store=store)
        adapter.reconcile()
        assert adapter.confirmed_blocks == (first,)
        assert len(store.events()) == 2
        now += timedelta(seconds=100)
        result, = adapter.expire_due()
        assert result.success
        assert adapter.reserved_count == 0
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        with pytest.raises(ValueError, match="new block ID"):
            adapter.apply(request)


def test_crash_after_install_keeps_write_ahead_reservation(tmp_path):
    path = tmp_path / "state.sqlite"
    firewall = FakeFirewall()
    request = BlockRequest("a", "10.10.10.30", "Manual test")

    def interrupted_apply(request, scope):
        firewall.state = RuleState.INSTALLED
        raise KeyboardInterrupt

    firewall.apply = interrupted_apply
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        with pytest.raises(KeyboardInterrupt):
            adapter.apply(request)
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        assert adapter.reserved_count == 1
        assert adapter.confirmed_blocks == ()
        adapter.reconcile()
        assert len(adapter.confirmed_blocks) == 1


def test_failed_removal_intent_survives_restart_and_poll_retries(tmp_path):
    path = tmp_path / "state.sqlite"
    firewall = FakeFirewall()
    request = BlockRequest("a", "10.10.10.30", "Manual test")
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        adapter.apply(request)
        firewall.remove_error = PermissionError("Denied")
        assert not adapter.remove(request).success
    firewall.remove_error = None
    with FirewallState(path) as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        assert adapter.expire_due()[0].success
        assert adapter.reserved_count == 0


def test_second_state_owner_is_rejected(tmp_path):
    path = tmp_path / "state.sqlite"
    with FirewallState(path):
        with pytest.raises(sqlite3.OperationalError):
            FirewallState(path)


def test_scope_change_rejected_before_transport(tmp_path):
    with FirewallState(tmp_path / "state.sqlite") as store:
        adapter = FirewallAdapter(FakeFirewall(), settings(), state_store=store)
        adapter.apply(BlockRequest("a", "10.10.10.30", "Manual test"))
        with pytest.raises(ValueError, match="differs"):
            FirewallAdapter(FakeFirewall(), settings(), max_blocks=10, state_store=store)


def test_failed_write_ahead_stops_mutation_and_further_requests():
    class BrokenState:
        def load(self):
            return None

        def save(self, *args):
            raise OSError("Disk full")

    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, settings(), state_store=BrokenState())
    request = BlockRequest("a", "10.10.10.30", "Manual test")
    with pytest.raises(OSError, match="Disk full"):
        adapter.apply(request)
    assert firewall.applied == []
    with pytest.raises(RuntimeError, match="journal failed"):
        adapter.apply(request)


def test_cleanup_preserves_unknown_rules(tmp_path):
    firewall = FakeFirewall()
    with FirewallState(tmp_path / "state.sqlite") as store:
        adapter = FirewallAdapter(firewall, settings(), state_store=store)
        adapter.apply(BlockRequest("a", "10.10.10.30", "Manual test"))
        firewall.verify_error = TimeoutError("Uncertain")
        assert adapter.cleanup()[0].rule_state == RuleState.UNKNOWN
        assert adapter.reserved_count == 1
