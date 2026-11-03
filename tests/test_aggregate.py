import math
import random
from dataclasses import replace

import pytest

from ddos_detector.aggregate import WindowAggregator, aggregate_packets
from ddos_detector.config import FEATURE_NAMES, Config
from ddos_detector.features import Packet, extract_features, window_start


def pkt(ts, src="10.0.0.1", proto="tcp", size=60, flags=0x02):
    return Packet(ts, src, proto, size, flags)


def random_packets(rng, n, span):
    packets = []
    for _ in range(n):
        proto = rng.choice(["tcp", "udp", "icmp"])
        flags = rng.choice([0x02, 0x12, 0x10, 0x04, None]) if proto == "tcp" else 0
        packets.append(Packet(rng.uniform(0, span), f"10.0.{rng.randrange(4)}.{rng.randrange(30)}",
                              proto, rng.randrange(40, 1500), flags))
    return sorted(packets, key=lambda p: p.ts)


def run(packets, config=Config(), **kw):
    return list(aggregate_packets(packets, config, **kw))


@pytest.mark.parametrize("seed", range(5))
@pytest.mark.parametrize("ws", [1.0, 0.5, 2.0])
def test_identical_to_extract_features(seed, ws):
    packets = random_packets(random.Random(seed), 400, 12)
    records = run(packets, Config(window_seconds=ws))
    expected = {}
    for p in packets:
        expected.setdefault(window_start(p.ts, ws), []).append(p)
    assert [r.window_start for r in records] == sorted(expected)
    for r in records:
        want = extract_features(expected[r.window_start], ws)
        assert r.vector == tuple(float(want[n]) for n in FEATURE_NAMES)
        assert r.packet_count == len(expected[r.window_start])
        assert r.window_end == r.window_start + ws and not r.capped


def test_boundaries_are_start_inclusive_end_exclusive():
    packets = [pkt(0.999999), pkt(1.0), pkt(59.999999999), pkt(60.0)]
    got = {r.window_start: r.packet_count for r in run(packets)}
    assert got == {0.0: 1, 1.0: 1, 59.0: 1, 60.0: 1}


def test_grace_accepts_out_of_order_then_drops_late():
    agg = WindowAggregator(Config(window_seconds=1.0, grace_seconds=1.0))
    assert agg.add(pkt(0.5)) == []
    assert agg.add(pkt(1.5)) == []
    assert agg.add(pkt(0.9)) == []  # window 0 still open: ends at 1.0, closes at 2.0
    out = agg.add(pkt(2.0))
    assert [(r.window_start, r.packet_count) for r in out] == [(0.0, 2)]
    assert agg.add(pkt(0.95)) == [] and agg.late_dropped == 1
    rest = agg.flush()
    assert [(r.window_start, r.packet_count) for r in rest] == [(1.0, 1), (2.0, 1)]
    assert agg.late_dropped == 1


def test_late_packet_never_changes_emitted_windows():
    agg = WindowAggregator()
    emitted = agg.add(pkt(0.1)) + agg.add(pkt(5.0))
    before = list(emitted)
    agg.add(pkt(0.2))
    assert emitted == before and agg.late_dropped == 1


def test_advance_without_packets_closes_windows():
    agg = WindowAggregator()
    agg.add(pkt(0.5))
    assert agg.advance(1.9) == []
    out = agg.advance(2.0)
    assert [r.window_start for r in out] == [0.0]
    assert agg.advance(100.0) == [] and agg.flush() == []
    assert agg.add(pkt(0.7)) == [] and agg.late_dropped == 1


def test_cap_limits_tracked_sources_only():
    config = Config(max_sources_per_window=5)
    packets = [pkt(0.1 + i * 0.01, src=f"10.0.0.{i}", size=100) for i in range(9)]
    packets += [pkt(0.5, src="10.0.0.0", size=100)]  # tracked source keeps counting
    (r,) = run(packets, config)
    full = extract_features(packets, 1.0)
    got = r.features
    assert r.capped and r.untracked_source_packets == 4 and r.packet_count == 10
    assert got["unique_src_ips"] == 5
    assert got["src_ip_entropy"] == pytest.approx(-(2 / 6 * math.log2(2 / 6) + 4 * (1 / 6) * math.log2(1 / 6)))
    for name in FEATURE_NAMES:
        if name not in ("unique_src_ips", "src_ip_entropy"):
            assert got[name] == full[name]


def test_default_cap_not_hit_for_small_windows():
    (r,) = run([pkt(0.1, src=f"10.0.0.{i}") for i in range(50)])
    assert not r.capped and r.untracked_source_packets == 0


def test_open_windows_stay_bounded_on_time_jump():
    config = Config(window_seconds=1.0, grace_seconds=1.0)
    agg = WindowAggregator(config)
    peak = 0
    for ts in [0.1, 0.5, 1.2, 2.2, 3.1, 1000.0, 1000.4, 1001.5]:
        agg.add(pkt(ts))
        peak = max(peak, len(agg._open))
    assert peak <= math.ceil(1.0 / 1.0) + 1
    assert [r.window_start for r in agg.flush()] == [1000.0, 1001.0]


def test_flush_emits_increasing_order_and_is_final():
    agg = WindowAggregator(Config(grace_seconds=10.0))
    out = []
    for ts in [3.0, 1.0, 2.0, 0.0, 4.5]:
        out += agg.add(pkt(ts))
    assert out == []
    flushed = agg.flush()
    assert [r.window_start for r in flushed] == [0.0, 1.0, 2.0, 3.0, 4.0]
    assert agg.flush() == []


def test_empty_windows_skipped_by_default_and_zero_filled_on_request():
    packets = [pkt(0.5), pkt(3.5)]
    assert [r.window_start for r in run(packets)] == [0.0, 3.0]
    records = run(packets, emit_empty=True)
    assert [(r.window_start, r.packet_count) for r in records] == [(0.0, 1), (1.0, 0), (2.0, 0), (3.0, 1)]
    assert records[1].vector == (0.0,) * 12


def test_deterministic_and_lazy():
    packets = random_packets(random.Random(7), 300, 8)
    assert run(packets) == run(packets)
    stream = aggregate_packets(iter(packets))
    first = next(stream)
    assert first.window_start == window_start(packets[0].ts, 1.0)


def test_non_finite_timestamp_rejected():
    with pytest.raises(ValueError):
        WindowAggregator().add(pkt(float("nan")))


def test_config_defaults():
    c = Config()
    assert c.grace_seconds == 1.0 and c.max_sources_per_window == 10000
    assert replace(c, grace_seconds=2.0).grace_seconds == 2.0
