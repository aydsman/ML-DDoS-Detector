import struct

import pytest

from ddos_detector.features import extract_features
from ddos_detector.normalize import SkipCounter, normalize_ip_packet


def ipv4(proto=6, total_length=60, ihl=5, frag=0, src="10.10.10.30", body=None, version=4):
    header = bytearray(ihl * 4)
    header[0] = (version << 4) | ihl
    header[2:4] = struct.pack("!H", total_length)
    header[6:8] = struct.pack("!H", frag)
    header[8] = 64
    header[9] = proto
    header[12:16] = bytes(map(int, src.split(".")))
    header[16:20] = bytes([10, 10, 10, 10])
    if body is None:
        body = bytearray(40)
        if proto == 6:
            body[12] = 5 << 4
            body[13] = 0x02  # SYN
    return bytes(header) + bytes(body)


def test_60_byte_ip_packet_three_in_one_second():
    raw = ipv4(proto=6, total_length=60)
    packets = [normalize_ip_packet(t, raw) for t in (0.1, 0.2, 0.3)]
    f = extract_features(packets, 1.0)
    assert packets[0].size == 60 and packets[0].flags == 0x02
    assert f["byte_rate"] == 180 and f["pkt_size_mean"] == 60 and f["pkt_size_std"] == 0


def test_size_is_total_length_not_captured_bytes_or_ethernet():
    raw = ipv4(total_length=1500)  # only 60 bytes captured
    assert normalize_ip_packet(0, raw).size == 1500
    assert normalize_ip_packet(0, raw, ethertype=0x0800).size == 1500


@pytest.mark.parametrize("proto,name", [(6, "tcp"), (17, "udp"), (1, "icmp")])
def test_supported_protocols(proto, name):
    pkt = normalize_ip_packet(1.5, ipv4(proto=proto), SkipCounter())
    assert pkt.proto == name and pkt.src == "10.10.10.30" and pkt.ts == 1.5


def test_non_first_fragment_counts_size_and_protocol_with_unknown_flags():
    skips = SkipCounter()
    pkt = normalize_ip_packet(0, ipv4(proto=6, frag=0x00B9), skips)
    assert pkt is not None and pkt.proto == "tcp" and pkt.size == 60 and pkt.flags is None
    assert not skips


def test_first_fragment_keeps_flags():
    assert normalize_ip_packet(0, ipv4(proto=6, frag=0x2000)).flags == 0x02


SKIP_CASES = [
    ("non_ip", b"\x00" * 40, None),
    ("non_ip", ipv4(), 0x0806),  # ARP ethertype
    ("ipv6", ipv4(version=6), None),
    ("ipv6", b"\x60" + b"\x00" * 39, None),
    ("ipv6", ipv4(), 0x86DD),
    ("truncated_header", b"", None),
    ("truncated_header", ipv4()[:19], None),
    ("truncated_header", ipv4(ihl=6)[:22], None),  # options cut off
    ("bad_length", ipv4(total_length=19), None),  # total < header
    ("bad_length", ipv4(ihl=4), None),  # IHL below minimum
    ("unsupported_protocol", ipv4(proto=47), None),
]


@pytest.mark.parametrize("reason,raw,ethertype", SKIP_CASES)
def test_skipped_packets_counted_by_reason(reason, raw, ethertype):
    skips = SkipCounter()
    assert normalize_ip_packet(0, raw, skips, ethertype) is None
    assert dict(skips) == {reason: 1}


def test_skips_optional_counter():
    assert normalize_ip_packet(0, b"") is None


def test_truncated_tcp_header_gives_unknown_flags_but_keeps_total_length():
    raw = ipv4(proto=6, total_length=60)[:30]  # IP header + 10 bytes of TCP
    pkt = normalize_ip_packet(0, raw, SkipCounter())
    assert pkt is not None and pkt.flags is None and pkt.size == 60


def test_real_zero_flags_distinguishable_from_unknown():
    body = bytearray(40)
    body[12] = 5 << 4  # TCP header present, all flags clear
    null_scan = normalize_ip_packet(0, ipv4(proto=6, body=body))
    unknown = normalize_ip_packet(0, ipv4(proto=6, frag=0x00B9))
    assert null_scan.flags == 0 and unknown.flags is None


def test_non_tcp_keeps_zero_flags():
    assert normalize_ip_packet(0, ipv4(proto=17)).flags == 0


def test_syn_features_ignore_unknown_flag_packets():
    syn = normalize_ip_packet(0.1, ipv4(proto=6))
    frag = normalize_ip_packet(0.2, ipv4(proto=6, frag=0x00B9))
    f = extract_features([syn, frag, frag], 1.0)
    assert f["syn_count"] == 1
    assert f["packet_rate"] == 3 and f["tcp_share"] == 1.0
    assert f["syn_no_ack_share"] == 1.0


@pytest.mark.parametrize("total_length", [20, 33])
def test_bytes_beyond_declared_ip_packet_cannot_supply_tcp_flags(total_length):
    # Link-layer padding/trailing bytes may resemble a TCP SYN, but are outside IP.
    raw = ipv4(proto=6, total_length=total_length)
    pkt = normalize_ip_packet(0, raw)
    assert pkt.size == total_length
    assert pkt.flags is None
    assert extract_features([pkt], 1.0)["syn_count"] == 0
