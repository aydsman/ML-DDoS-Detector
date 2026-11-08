"""Regression for issue #26: the independent references must reject malformed IPv4 lengths.

The fixture is specified here, byte by byte, with the standard library only.  It has four
valid inbound packets plus one packet whose IPv4 Total Length (10) is smaller than its own
20-byte header.  Valid truncated captures and non-first fragments must be kept.
"""
import struct
from decimal import Decimal

import pytest

from tools import verify_pcap_features as verify

VICTIM = "10.10.10.10"
TSHARK = verify.find_tshark()


def _ip(src, dst, proto, payload, total_length=None, flags_frag=0):
    total = total_length if total_length is not None else 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, flags_frag, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\x00" * 6 + b"\x00" * 5 + b"\x01" + b"\x08\x00" + header + payload


def _tcp(flags, size=20):
    return struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, 5 << 4, flags, 0, 0, 0)[:size]


def _write(path, frames):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in frames:
            handle.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)),
                                     len(data), len(data)))
            handle.write(data)


@pytest.fixture
def malformed_pcap(tmp_path):
    A, B = "10.10.10.30", "10.10.10.31"
    frames = [
        # first TCP fragment (MF set): SYN, Total Length 60
        (200.1, _ip(A, VICTIM, 6, _tcp(0x02) + b"\x00" * 20, flags_frag=0x2000)),
        # matching non-first fragment: offset 5, TCP flags unknown, Total Length 40
        (200.2, _ip(A, VICTIM, 6, b"\x00" * 20, flags_frag=5)),
        # valid TCP capture truncated after 10 TCP bytes; declared Total Length stays 100
        (200.3, _ip(B, VICTIM, 6, _tcp(0x02, size=10), total_length=100)),
        # UDP, Total Length 40... 8-byte header + 12 payload bytes
        (200.4, _ip(B, VICTIM, 17, struct.pack("!HHHH", 1, 2, 20, 0) + b"\x00" * 12)),
        # malformed: Total Length 10 is smaller than the 20-byte IPv4 header
        (200.5, _ip(A, VICTIM, 6, _tcp(0x02), total_length=10)),
    ]
    path = tmp_path / "malformed.pcap"
    _write(path, frames)
    return path


def test_scope_rule():
    assert verify.valid_ipv4_lengths(60, 20)
    assert verify.valid_ipv4_lengths(20, 20)
    assert not verify.valid_ipv4_lengths(10, 20)
    assert not verify.valid_ipv4_lengths(60, 16)
    assert not verify.valid_ipv4_lengths(None, 20)
    assert not verify.valid_ipv4_lengths(60, None)


def _check(rows, skipped):
    assert [r[3] for r in rows] == [60, 40, 100, 40]
    assert [r[4] for r in rows] == [0x02, None, None, 0]
    assert [r[0] for r in rows] == [Decimal(t) for t in ("200.1", "200.2", "200.3", "200.4")]
    assert len(skipped) == 1 and "bad_length" in skipped[0][1]


def test_scapy_reference_rejects_malformed_length_and_keeps_valid_cases(malformed_pcap):
    skipped = []
    rows = verify.scapy_rows(str(malformed_pcap), VICTIM, skipped)
    _check(rows, skipped)


@pytest.mark.skipif(TSHARK is None, reason="tshark not found")
def test_tshark_reference_rejects_malformed_length_and_keeps_valid_cases(malformed_pcap):
    skipped = []
    rows = verify.tshark_rows(str(malformed_pcap), VICTIM, TSHARK, skipped)
    kept = [r[3] for r in rows]
    # tshark may drop the malformed record itself or hand it to us; either way it is not kept
    assert kept == [60, 40, 100, 40]
    assert 10 not in kept


@pytest.mark.parametrize("engine", ["scapy", "tshark"])
def test_package_and_reference_agree_on_the_four_valid_packets(malformed_pcap, engine):
    if engine == "tshark":
        if TSHARK is None:
            pytest.skip("tshark not found")
        rows = verify.tshark_rows(str(malformed_pcap), VICTIM, TSHARK)
    else:
        rows = verify.scapy_rows(str(malformed_pcap), VICTIM)
    result = verify.compare(malformed_pcap, rows)
    assert result["problems"] == []
    assert result["packets"] == 4
