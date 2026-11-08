import struct

import pytest

from ddos_detector.pcap import PcapError, read_pcap

FRAMES = [(1.5, b"\x01" * 60), (2.25, b"\x02" * 14)]


def build_pcap(path, records=FRAMES, endian="<", nano=False, linktype=1, orig_extra=0):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    data = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    scale = 10**9 if nano else 10**6
    for ts, frame in records:
        sec, frac = int(ts), round((ts - int(ts)) * scale)
        data += struct.pack(endian + "IIII", sec, frac, len(frame), len(frame) + orig_extra) + frame
    path.write_bytes(data)
    return path


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_reads_all_endian_and_precision_variants(tmp_path, endian, nano):
    path = build_pcap(tmp_path / "a.pcap", endian=endian, nano=nano)
    assert list(read_pcap(path)) == FRAMES


def test_reader_is_lazy(tmp_path):
    path = build_pcap(tmp_path / "a.pcap")
    records = read_pcap(path)
    assert next(records) == FRAMES[0]


def test_empty_capture_yields_nothing(tmp_path):
    assert list(read_pcap(build_pcap(tmp_path / "a.pcap", records=[]))) == []


def test_snaplen_truncated_record_is_kept(tmp_path):
    path = build_pcap(tmp_path / "a.pcap", orig_extra=1000)
    assert list(read_pcap(path)) == FRAMES


def test_incl_len_larger_than_orig_len_is_rejected(tmp_path):
    path = build_pcap(tmp_path / "a.pcap", records=[(1.0, b"\x00" * 20)])
    raw = bytearray(path.read_bytes())
    raw[36:40] = struct.pack("<I", 10)  # orig_len of record 0
    path.write_bytes(bytes(raw))
    with pytest.raises(PcapError, match="bad length"):
        list(read_pcap(path))


def test_truncated_record_body_raises_after_good_records(tmp_path):
    path = build_pcap(tmp_path / "a.pcap")
    path.write_bytes(path.read_bytes()[:-5])
    records = read_pcap(path)
    assert next(records) == FRAMES[0]
    with pytest.raises(PcapError, match="truncated"):
        next(records)


def test_truncated_record_header_raises(tmp_path):
    path = build_pcap(tmp_path / "a.pcap", records=[])
    path.write_bytes(path.read_bytes() + b"\x00" * 7)
    with pytest.raises(PcapError, match="record header"):
        list(read_pcap(path))


def test_short_file_and_bad_magic(tmp_path):
    short = tmp_path / "s.pcap"
    short.write_bytes(b"\xd4\xc3\xb2")
    with pytest.raises(PcapError, match="too short"):
        list(read_pcap(short))
    bad = tmp_path / "b.pcap"
    bad.write_bytes(b"\x00" * 40)
    with pytest.raises(PcapError, match="bad magic"):
        list(read_pcap(bad))


def test_pcapng_is_rejected_with_conversion_hint(tmp_path):
    path = tmp_path / "x.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError, match="convert"):
        list(read_pcap(path))


def test_non_ethernet_linktype_is_rejected(tmp_path):
    path = build_pcap(tmp_path / "a.pcap", linktype=113)
    with pytest.raises(PcapError, match="not Ethernet"):
        list(read_pcap(path))
