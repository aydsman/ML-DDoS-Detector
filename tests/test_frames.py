import struct
from pathlib import Path

import pytest

from ddos_detector.frames import frame_to_packet, iter_packets
from ddos_detector.normalize import SkipCounter
from test_pcap import build_pcap
from tools.lab_window_summary import summarize

VICTIM = "10.10.10.10"
LAB_PCAP = Path(__file__).resolve().parent.parent / "data/lab-runs/pr16-syn-run1/syn1.pcap"


def eth(ethertype, payload, pad=0):
    return bytes(12) + struct.pack("!H", ethertype) + payload + bytes(pad)


def ipv4(proto=6, total_length=40, src="10.10.10.30", dst=VICTIM, flags=0x02):
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", total_length)
    header[8] = 64
    header[9] = proto
    header[12:16] = bytes(map(int, src.split(".")))
    header[16:20] = bytes(map(int, dst.split(".")))
    body = bytearray(max(total_length - 20, 0))
    if proto == 6 and len(body) >= 14:
        body[12] = 5 << 4
        body[13] = flags
    return bytes(header) + bytes(body)


def test_tcp_syn_to_victim():
    r = frame_to_packet(eth(0x0800, ipv4()), 3.0, VICTIM)
    assert r.skip is None
    p = r.packet
    assert (p.ts, p.src, p.proto, p.size, p.flags) == (3.0, "10.10.10.30", "tcp", 40, 0x02)


def test_udp_and_icmp_to_victim():
    udp = frame_to_packet(eth(0x0800, ipv4(proto=17, total_length=60)), 0, VICTIM).packet
    icmp = frame_to_packet(eth(0x0800, ipv4(proto=1, total_length=84)), 0, VICTIM).packet
    assert (udp.proto, udp.size, udp.flags) == ("udp", 60, 0)
    assert (icmp.proto, icmp.size, icmp.flags) == ("icmp", 84, 0)


def test_default_victim_ip_comes_from_config():
    assert frame_to_packet(eth(0x0800, ipv4()), 0).packet is not None


@pytest.mark.parametrize("ethertype,payload,reason", [
    (0x0806, bytes(28), "non_ip"),  # ARP
    (0x86DD, bytes(40), "ipv6"),
    (0x88CC, bytes(20), "non_ip"),
    (0x8100, bytes(4) + ipv4(), "vlan_tagged"),
    (0x88A8, bytes(4) + ipv4(), "vlan_tagged"),
])
def test_non_ipv4_and_vlan_frames_are_skipped(ethertype, payload, reason):
    r = frame_to_packet(eth(ethertype, payload), 0, VICTIM)
    assert r.packet is None and r.skip == reason


@pytest.mark.parametrize("dst,reason", [
    ("10.10.10.20", "not_inbound"),
    ("255.255.255.255", "broadcast"),
    ("224.0.0.251", "multicast"),
    ("239.255.255.250", "multicast"),
])
def test_destination_filter(dst, reason):
    r = frame_to_packet(eth(0x0800, ipv4(dst=dst)), 0, VICTIM)
    assert r.packet is None and r.skip == reason


def test_ethernet_padding_beyond_total_length_is_ignored():
    r = frame_to_packet(eth(0x0800, ipv4(total_length=40), pad=6), 0, VICTIM)
    assert r.packet.size == 40 and r.packet.flags == 0x02


def test_truncated_frames():
    assert frame_to_packet(bytes(10), 0, VICTIM).skip == "truncated_frame"
    assert frame_to_packet(eth(0x0800, ipv4()[:12]), 0, VICTIM).skip == "truncated_header"
    assert frame_to_packet(eth(0x0800, b""), 0, VICTIM).skip == "truncated_header"


def test_snaplen_cut_tcp_header_gives_unknown_flags():
    r = frame_to_packet(eth(0x0800, ipv4(total_length=60)[:30]), 0, VICTIM)
    assert r.packet.size == 60 and r.packet.flags is None


def test_unsupported_protocol_reason_comes_from_normalize():
    assert frame_to_packet(eth(0x0800, ipv4(proto=47)), 0, VICTIM).skip == "unsupported_protocol"


def test_iter_packets_records_skips(tmp_path):
    frames = [
        (1.0, eth(0x0800, ipv4())),
        (2.0, eth(0x0806, bytes(28))),
        (3.0, eth(0x0800, ipv4(dst="10.10.10.99"))),
        (4.0, eth(0x0800, ipv4(proto=17, total_length=28))),
    ]
    path = build_pcap(tmp_path / "a.pcap", records=frames)
    skips = SkipCounter()
    packets = list(iter_packets(path, VICTIM, skips))
    assert [p.ts for p in packets] == [1.0, 4.0]
    assert skips == {"non_ip": 1, "not_inbound": 1}


def test_lab_summary_counts_skips_and_excludes_edge_windows(tmp_path):
    path = build_pcap(tmp_path / "summary.pcap", records=[
        (1.0, eth(0x0800, ipv4())),
        (2.0, eth(0x0806, bytes(28))),
        (2.1, eth(0x0800, ipv4())),
        (2.2, eth(0x0800, ipv4(proto=17, total_length=28))),
        (3.0, eth(0x0800, ipv4())),
    ])

    result = summarize(path)
    assert result["skipped"] == {"non_ip": 1}
    assert result["windows_used"] == 1
    assert result["windows_dropped_edges"] == 2
    assert result["total_pps"] == {"median": 2, "max": 2}
    assert result["groups"]["10.10.10.30/tcp"]["share_max"] == 0.5


def test_scapy_cross_check(tmp_path):
    from scapy.all import ICMP, IP, TCP, UDP, Ether, wrpcap

    pkts = [
        Ether() / IP(src="10.10.10.30", dst=VICTIM) / TCP(dport=80, flags="S"),
        Ether() / IP(src="10.10.10.31", dst=VICTIM) / TCP(dport=80, flags="SA") / (b"x" * 30),
        Ether() / IP(src="10.10.10.32", dst=VICTIM) / UDP(dport=53) / (b"y" * 100),
        Ether() / IP(src="10.10.10.33", dst=VICTIM) / ICMP(),
    ]
    for i, p in enumerate(pkts):
        p.time = 1000.0 + i * 0.5
    path = tmp_path / "s.pcap"
    wrpcap(str(path), pkts)

    ours = list(iter_packets(path, VICTIM))
    assert len(ours) == len(pkts)
    for mine, theirs in zip(ours, pkts):
        ip = Ether(bytes(theirs))[IP]  # re-dissect so computed fields (len) are filled
        l4 = ip.payload
        assert mine.ts == pytest.approx(float(theirs.time), abs=1e-5)
        assert mine.src == ip.src
        assert mine.size == ip.len
        assert mine.proto == {TCP: "tcp", UDP: "udp", ICMP: "icmp"}[type(l4)]
        assert mine.flags == (int(l4.flags) if isinstance(l4, TCP) else 0)


@pytest.mark.skipif(not LAB_PCAP.exists(), reason="lab pcap not present")
def test_real_lab_syn_run():
    skips = SkipCounter()
    packets = list(iter_packets(LAB_PCAP, VICTIM, skips))
    # tshark: 50 SYN + 50 RST from 10.10.10.30 to the victim, 50 SYN-ACK from the victim, 2 ARP
    assert len(packets) == 100
    assert all(p.src == "10.10.10.30" and p.proto == "tcp" and p.size == 40 for p in packets)
    assert sum(p.flags == 0x02 for p in packets) == 50
    assert sum(p.flags == 0x04 for p in packets) == 50
    assert skips == {"not_inbound": 50, "non_ip": 2}
