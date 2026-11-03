import pytest

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.features import Packet, WindowAccumulator, extract_features, window_start, windows


def test_empty_window_has_all_features():
    assert set(extract_features([], 1.0)) == set(FEATURE_NAMES)


def test_syn_flood_looks_different_from_benign():
    flood = [Packet(0.0, f"10.0.0.{i}", "tcp", 60, 0x02) for i in range(200)]
    benign = [Packet(0.0, "10.0.0.1", "tcp", 500, 0x10) for _ in range(20)]
    f, b = extract_features(flood, 1.0), extract_features(benign, 1.0)
    assert f["syn_count"] > b["syn_count"]
    assert f["unique_src_ips"] > b["unique_src_ips"]


def test_windows_split():
    pkts = [Packet(t, "a", "udp", 100) for t in (0.1, 0.5, 1.2, 2.7)]
    assert [len(b) for _, b in windows(pkts, 1.0)] == [2, 1, 1]


def test_known_ipv4_packet_byte_statistics():
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    # Verify the IP byte definition independently of the feature calculation.
    wire_packet = IP(bytes(IP() / TCP() / Raw(b"x" * 20)))
    assert wire_packet.len == 60  # 20 IP + 20 TCP + 20 payload, no Ethernet
    packets = [Packet(t, "10.10.10.30", "tcp", wire_packet.len, 0x02)
               for t in (0.1, 0.2, 0.3)]
    features = extract_features(packets, 1.0)
    assert features["byte_rate"] == 180
    assert features["pkt_size_mean"] == 60
    assert features["pkt_size_std"] == 0


def test_size_statistics_match_expanded_population_statistics():
    import random
    import statistics

    rng = random.Random(7)
    sizes = [rng.choice((40, 49, 60, 100, 576, 1500)) for _ in range(5000)]
    features = extract_features([Packet(0.0, "a", "udp", s) for s in sizes], 2.0)
    assert features["byte_rate"] == sum(sizes) / 2.0
    assert features["pkt_size_mean"] == statistics.mean(sizes)
    assert features["pkt_size_std"] == pytest.approx(statistics.pstdev(sizes), rel=1e-12)


def test_finalization_memory_does_not_grow_with_packet_count():
    import tracemalloc

    def peak_bytes(count):
        acc = WindowAccumulator(max_sources=2)
        p = Packet(0.0, "10.0.0.1", "tcp", 60, 0x02)
        for _ in range(count):
            acc.add(p)
        tracemalloc.start()
        try:
            acc.features(1.0)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    small, large = peak_bytes(10_000), peak_bytes(100_000)
    assert large < 16_384  # histogram has one entry; old code needed ~800 KB at 100k
    assert large <= small * 2 + 4096


def test_window_start_is_epoch_aligned():
    assert window_start(1700000000.7, 1.0) == 1700000000
    assert window_start(7.5, 5.0) == 5.0
    assert window_start(10.0, 5.0) == 10.0  # start-inclusive


def test_windows_aligned_to_epoch_not_first_packet():
    pkts = [Packet(t, "a", "udp", 100) for t in (10.9, 11.0, 11.5, 14.2)]
    got = [(s, len(b)) for s, b in windows(pkts, 1.0)]
    assert got == [(10, 1), (11, 2), (12, 0), (13, 0), (14, 1)]


def test_window_end_is_exclusive_and_alignment_is_origin_independent():
    a = [Packet(t, "a", "udp", 100) for t in (0.0, 0.999, 1.0)]
    b = a[1:]  # same packets, different first packet
    assert [(s, len(x)) for s, x in windows(a, 1.0)] == [(0, 2), (1, 1)]
    assert [(s, len(x)) for s, x in windows(b, 1.0)] == [(0, 1), (1, 1)]
