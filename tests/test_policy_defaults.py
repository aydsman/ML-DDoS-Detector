import ipaddress
import json
from pathlib import Path

from ddos_detector.config import Config
from ddos_detector.features import Packet
from ddos_detector.aggregate import aggregate_packets

PATH = Path(__file__).resolve().parents[1] / "docs" / "policy-defaults.json"


def defaults():
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_safe_startup_defaults():
    d = defaults()
    assert d["mode"] == "monitor_only"
    assert d["allowlist"]["verified"] is False
    assert d["attribution"]["required_consecutive_windows"] == 3
    assert d["blocks"]["block_seconds"] == 300
    assert d["blocks"]["max_active_blocks"] == 20
    assert d["attribution"]["share_basis"] == "all_selected_packets"
    assert d["scope"]["ip_version"] == 4
    assert d["scope"]["protocols"] == ["tcp", "udp", "icmp"]


def test_no_invented_thresholds():
    """Thresholds stay unset until validation evidence exists; unset never qualifies."""
    a = defaults()["attribution"]
    assert a["min_share"] is None
    assert a["syn_rate_threshold"] is None
    assert set(a["packet_rate_thresholds"]) == {"tcp", "udp", "icmp"}
    assert all(v is None for v in a["packet_rate_thresholds"].values())


def test_matches_shared_config():
    d = defaults()
    cfg = Config()
    assert d["scope"]["protected_ip"] == cfg.victim_ip
    assert d["window"]["window_seconds"] == cfg.window_seconds
    assert d["window"]["grace_seconds"] == cfg.grace_seconds


def test_allowlist_entries_are_valid_and_exclude_attacker():
    entries = [e["address"] for e in defaults()["allowlist"]["entries"]]
    networks = [ipaddress.ip_network(e) for e in entries]
    assert all(ipaddress.ip_address("10.10.10.30") not in network for network in networks)
    for must in ("10.10.10.10", "10.10.10.20"):
        assert ipaddress.ip_address(must) in [n.network_address for n in networks if n.prefixlen == 32]
    assert any(ipaddress.ip_address("127.0.0.1") in n for n in networks)


def test_epoch_window_origin_matches_aggregator():
    """The documented origin rule is what the shared aggregator does offline and live."""
    packets = [Packet(100.1, "10.10.10.30", "udp", 60, 0), Packet(100.9, "10.10.10.30", "udp", 60, 0),
               Packet(101.0, "10.10.10.30", "udp", 60, 0)]
    records = list(aggregate_packets(packets))
    assert [(r.window_start, r.window_end, r.packet_count) for r in records] == [(100.0, 101.0, 2), (101.0, 102.0, 1)]


def test_missing_interval_is_not_emitted_as_traffic():
    """A gap produces no record by default, so the policy consumer must see the index jump."""
    packets = [Packet(100.5, "10.10.10.30", "udp", 60, 0), Packet(103.5, "10.10.10.30", "udp", 60, 0)]
    starts = [r.window_start for r in aggregate_packets(packets)]
    assert starts == [100.0, 103.0]
