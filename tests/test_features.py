from ddos_detector.config import FEATURE_NAMES
from ddos_detector.features import Packet, extract_features, windows


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
