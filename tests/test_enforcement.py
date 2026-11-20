from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from ddos_detector.aggregate import SourceCount, WindowRecord, aggregate_packets
from ddos_detector.config import FEATURE_NAMES, Config
from ddos_detector.enforcement import Enforcement, PolicySettings, SourcePolicy
from ddos_detector.features import Packet
from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_cli import report
from ddos_detector.firewall_contract import RuleState
from ddos_detector.firewall_state import FirewallState


def scope():
    return FirewallScope("enp0s8", "10.10.10.10", ("10.0.2.0/24",), True)


def settings(**kwargs):
    return PolicySettings((("tcp", 100), ("udp", 100), ("icmp", None)), 100, 0.1,
                          review_ref="synthetic test only", max_window_age_seconds=5, **kwargs)


def window(start, counts=None, **kwargs):
    counts = counts if counts is not None else (SourceCount("10.10.10.30", "tcp", 4200, 4200),
                                               SourceCount("10.10.10.20", "tcp", 12))
    record = WindowRecord(start, start + 1, (0,) * len(FEATURE_NAMES), sum(row.packets for row in counts),
                          source_counts=tuple(counts), **kwargs)
    event = {"window_start": start, "window_end": start + 1, "packet_count": record.packet_count,
             "scored": True, "predicted_attack": True}
    return event, record


class Rules:
    def __init__(self):
        self.rules = set()
        self.installs = []
        self.unknown = False
        self.fail_remove = False
        self.resets = 0

    def apply(self, request, scope):
        self.rules.add(request.block_id)
        self.installs.append(request)

    def verify(self, request, scope):
        return RuleState.UNKNOWN if self.unknown else (RuleState.INSTALLED if request.block_id in self.rules else RuleState.ABSENT)

    def remove(self, request, scope):
        if self.fail_remove:
            raise PermissionError("test removal failure")
        self.rules.discard(request.block_id)

    def cleanup_empty_table(self):
        assert not self.rules
        self.resets += 1

    def check_inventory(self, requests, scope):
        assert self.rules <= {r.block_id for r in requests}


def test_source_counts_are_same_window_and_unknown_flags_never_invent_syns():
    packets = [Packet(100.1, "10.10.10.30", "tcp", 40, 2),
               Packet(100.2, "10.10.10.30", "tcp", 40, None),
               Packet(100.3, "10.10.10.30", "tcp", 40, 18),
               Packet(100.4, "10.10.10.30", "udp", 28),
               Packet(101, "10.10.10.30", "tcp", 40, 2)]
    first, second = aggregate_packets(packets)
    assert first.source_counts == (SourceCount("10.10.10.30", "tcp", 3, 1), SourceCount("10.10.10.30", "udp", 1))
    assert second.source_counts == (SourceCount("10.10.10.30", "tcp", 1, 1),)
    assert first.features["syn_count"] == 1 and len(first.vector) == 12


def test_attribution_storage_remains_bounded_with_source_cap():
    records = list(aggregate_packets([Packet(1.1, "10.10.10.30", "udp", 28),
                                     Packet(1.2, "10.10.10.31", "udp", 28)],
                                    Config(max_sources_per_window=1)))
    assert records[0].capped and records[0].packet_count == 2
    assert records[0].source_counts == (SourceCount("10.10.10.30", "udp", 1),)
    policy = SourcePolicy(settings(), scope())
    event, _ = window(1)
    event["packet_count"] = 2
    assert policy.evaluate(event, records[0]) == []


def test_three_windows_acceptance_example_in_monitor_only_never_contacts_firewall():
    events = []
    controller = Enforcement(SourcePolicy(settings(), scope()), events.append)
    for start in (100, 101, 102):
        controller.handle(*window(start))
    rows = events[-1]["candidates"]
    assert len(rows) == 1 and rows[0]["source_ip"] == "10.10.10.30"
    assert rows[0]["consecutive_windows"] == 3 and rows[0]["eligible"]
    assert rows[0]["packet_share"] == 4200 / 4212 and rows[0]["decision"] == "alert"
    assert not any(e["record_type"] == "block_requested" for e in events)


@pytest.mark.parametrize("gap", ["missing", "benign", "unscored", "empty", "capped", "nonqualifying", "failure"])
def test_gaps_and_nonqualifying_windows_break_streaks(gap):
    policy = SourcePolicy(settings(), scope())
    policy.evaluate(*window(100))
    policy.evaluate(*window(101))
    if gap == "failure":
        policy.reset()
    elif gap != "missing":
        event, record = window(102, [] if gap == "empty" else None, capped=gap == "capped")
        if gap == "benign":
            event["predicted_attack"] = False
        if gap == "unscored":
            event["scored"] = False
        if gap == "nonqualifying":
            event, record = window(102, [SourceCount("10.10.10.30", "udp", 1)])
        assert policy.evaluate(event, record) == []
    result = policy.evaluate(*window(103))
    assert result[0]["consecutive_windows"] == 1 and not result[0]["eligible"]


def test_defaults_do_not_qualify_or_enable_automatic():
    document = json.loads(Path("docs/policy-defaults.json").read_text())
    policy = SourcePolicy(PolicySettings.from_document(document), scope())
    for start in range(100, 105):
        assert policy.evaluate(*window(start)) == []
    with pytest.raises(ValueError, match="policy_review_ref"):
        policy.settings.require_automatic(scope())


@pytest.mark.parametrize("change", [{"min_share": None}, {"max_window_age_seconds": None},
                                    {"review_ref": ""}, {"review_ref": None}])
def test_automatic_requires_reviewed_complete_settings(change):
    with pytest.raises(ValueError):
        replace(settings(), **change).require_automatic(scope())


def test_source_protocols_have_independent_streaks_and_strict_rate_boundary():
    policy = SourcePolicy(settings(), scope())
    for start, proto in [(100, "tcp"), (101, "udp"), (102, "tcp")]:
        rows = policy.evaluate(*window(start, [SourceCount("10.10.10.30", proto, 101)]))
        assert rows[0]["consecutive_windows"] == 1
    assert policy.evaluate(*window(103, [SourceCount("10.10.10.30", "udp", 100)])) == []


@pytest.mark.parametrize("source", ["10.10.10.10", "10.10.10.20", "10.0.2.2", "127.0.0.1", "224.0.0.1", "0.0.0.0"])
def test_protected_sources_never_qualify(source):
    assert SourcePolicy(settings(), scope()).evaluate(*window(100, [SourceCount(source, "udp", 1000)])) == []


def test_automatic_dedup_cap_priority_unknown_expiry_and_repeatable_reset(tmp_path):
    now = [datetime.fromtimestamp(101.1, timezone.utc)]
    transport, emitted = Rules(), []
    with FirewallState(tmp_path / "state.sqlite") as store:
        adapter = FirewallAdapter(transport, scope(), max_blocks=1, clock=lambda: now[0], state_store=store)
        controller = Enforcement(SourcePolicy(settings(), scope()), emitted.append, mode="automatic", adapter=adapter)
        counts = [SourceCount("10.10.10.100", "udp", 200), SourceCount("10.10.10.30", "tcp", 200, 200),
                  SourceCount("10.10.10.30", "udp", 200)]
        for start in (100, 101, 102, 103):
            now[0] = datetime.fromtimestamp(start + 1.1, timezone.utc)
            controller.handle(*window(start, counts))
        assert len(transport.installs) == 1 and transport.installs[0].source_ip == "10.10.10.30"
        first, = adapter.confirmed_blocks
        assert first.expires_at - first.blocked_at == timedelta(seconds=300)
        transport.unknown = True
        controller.tick()
        assert report(adapter)["blocks"] == [] and adapter.reserved_count == 1
        transport.unknown = False
        controller.tick()
        assert adapter.confirmed_blocks == (first,)
        now[0] = first.expires_at
        controller.tick()
        assert adapter.reserved_count == 0
        # A previously saturated streak must start over after confirmed expiry.
        start = int(now[0].timestamp())
        controller.handle(*window(start - 1))
        assert emitted[-1]["candidates"][0]["consecutive_windows"] == 1
        assert len(transport.installs) == 1
        assert controller.cleanup() and controller.cleanup() and transport.resets == 2


def test_failed_cleanup_retains_journal_then_recovers(tmp_path):
    path, transport = tmp_path / "state.sqlite", Rules()
    with FirewallState(path) as store:
        adapter = FirewallAdapter(transport, scope(), clock=lambda: datetime.fromtimestamp(103.1, timezone.utc), state_store=store)
        controller = Enforcement(SourcePolicy(settings(), scope()), lambda e: None, mode="automatic", adapter=adapter)
        for start in (100, 101, 102):
            controller.handle(*window(start))
        transport.fail_remove = True
        assert controller.cleanup() is False and adapter.reserved_count == 1
    transport.fail_remove = False
    with FirewallState(path) as store:
        adapter = FirewallAdapter(transport, scope(), state_store=store)
        adapter.reconcile()
        controller = Enforcement(SourcePolicy(settings(), scope()), lambda e: None, mode="automatic", adapter=adapter)
        assert controller.cleanup() and adapter.reserved_count == 0


def test_stale_windows_and_mode_changes_reset_streaks():
    adapter = FirewallAdapter(Rules(), scope(), clock=lambda: datetime.fromtimestamp(103.1, timezone.utc))
    events = []
    controller = Enforcement(SourcePolicy(settings(), scope()), events.append, mode="automatic", adapter=adapter)
    controller.handle(*window(100))
    controller.handle(*window(101))
    controller.set_mode("monitor_only")
    controller.set_mode("automatic")
    controller.handle(*window(102))
    assert events[-1]["candidates"][0]["consecutive_windows"] == 1 and not adapter.pending_requests
    controller.handle(*window(10))
    assert events[-1]["reason"] == "stale_or_future_window"


def test_aggregate_alert_without_source_accounting_is_rejected():
    event, record = window(100)
    with pytest.raises(ValueError, match="all selected"):
        SourcePolicy(settings(), scope()).evaluate(event, replace(record, source_counts=()))


def test_bounded_runtime_audit_keeps_latest_state_and_failures_in_journal(tmp_path):
    rules = Rules()
    with FirewallState(tmp_path / "state.sqlite") as store:
        adapter = FirewallAdapter(rules, scope(), state_store=store, audit_limit=1)
        from ddos_detector.firewall_contract import BlockRequest
        a = BlockRequest("a", "10.10.10.30", "test")
        b = BlockRequest("b", "10.10.10.31", "test")
        adapter.apply(a)
        rules.unknown = True
        adapter.verify(a)
        rules.unknown = False
        adapter.apply(b)
        assert len(adapter.audit_events) == 1 and adapter.had_failures
        assert len(store.events()) == 3
        assert report(adapter)["uncertain_block_ids"] == ["a"]
        assert [row["id"] for row in report(adapter)["blocks"]] == ["b"]


def test_failed_request_audit_prevents_installation():
    rules = Rules()
    adapter = FirewallAdapter(rules, scope(), clock=lambda: datetime.fromtimestamp(103.1, timezone.utc))

    def emit(event):
        if event["record_type"] == "block_requested":
            raise OSError("test audit full")

    controller = Enforcement(SourcePolicy(settings(), scope()), emit, mode="automatic", adapter=adapter)
    controller.handle(*window(100))
    controller.handle(*window(101))
    with pytest.raises(OSError, match="audit full"):
        controller.handle(*window(102))
    assert not rules.installs and adapter.reserved_count == 0


def test_external_disappearance_releases_cap_and_resets_source_streak():
    rules = Rules()
    adapter = FirewallAdapter(rules, scope(), clock=lambda: datetime.fromtimestamp(104.1, timezone.utc))
    emitted = []
    controller = Enforcement(SourcePolicy(settings(), scope()), emitted.append, mode="automatic", adapter=adapter)
    for start in (100, 101, 102):
        controller.handle(*window(start))
    rules.rules.clear()  # Simulate an external deletion, not controller cleanup.
    controller.handle(*window(103))
    assert adapter.reserved_count == 0
    assert emitted[-1]["candidates"][0]["consecutive_windows"] == 1
    assert len(rules.installs) == 1
