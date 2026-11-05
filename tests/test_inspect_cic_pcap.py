import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import inspect_cic_pcap as tool


def _ip_packet(src, dst, proto, l4, total_length=None, frag=0):
    total = total_length if total_length is not None else 20 + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, frag, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\x00" * 12 + b"\x08\x00" + header + l4


def _tcp(flags):
    return struct.pack("!HHIIBBHHH", 1234, 80, 0, 0, 5 << 4, flags, 0, 0, 0)


def _udp(dport):
    return struct.pack("!HHHH", 1234, dport, 8, 0)


def _write_pcap(path, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            handle.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)))
            handle.write(data)


class InspectCicPcapTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "piece"
        _write_pcap(self.path, [
            (100.0, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x02))),
            (100.5, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x04))),
            (101.0, _ip_packet("172.16.0.5", "192.168.50.1", 17, _udp(53))),
            (101.5, _ip_packet("172.16.0.5", "10.0.0.9", 6, _tcp(0x02))),
            (102.0, b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 40),
        ])

    def tearDown(self):
        self.dir.cleanup()

    def test_full_scan_counts_and_victim_filter(self):
        r = tool.inspect_piece(str(self.path), "192.168.50.1", None, True)
        self.assertEqual(r["scan"]["packets_read"], 5)
        self.assertTrue(r["scan"]["reached_end_of_file"])
        self.assertEqual(r["scan"]["non_ipv4_or_unparsed"], 1)
        self.assertEqual(r["tcp_flag_classes_to_victim"], {"syn": 1, "rst": 1})
        self.assertEqual(r["udp_top_dst_ports_to_victim"], [(53, 1)])
        self.assertEqual(r["top_sources_to_victim"], [("172.16.0.5", 3)])
        self.assertEqual(r["time"]["first_utc"], "1970-01-01T00:01:40+00:00")
        self.assertEqual(len(r["sha256"]), 64)

    def test_limit_is_reported_as_truncation(self):
        r = tool.inspect_piece(str(self.path), None, 2, False)
        self.assertEqual(r["scan"]["packets_read"], 2)
        self.assertFalse(r["scan"]["reached_end_of_file"])
        self.assertIsNone(r["sha256"])

    def test_non_first_fragments_are_not_read_as_transport_headers(self):
        path = Path(self.dir.name) / "frag"
        # offset=1: payload continuation whose bytes look like SYN flags / UDP port 53
        tcp_like = b"\x00" * 13 + b"\x02" + b"\x00" * 6
        udp_like = b"\x00\x00\x00\x35" + b"\x00" * 4
        _write_pcap(path, [
            (1.0, _ip_packet("172.16.0.5", "192.168.50.1", 6, tcp_like, frag=1)),
            (1.1, _ip_packet("172.16.0.5", "192.168.50.1", 17, udp_like, frag=1)),
            (1.2, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x02))),
        ])
        r = tool.inspect_piece(str(path), "192.168.50.1", None, False)
        self.assertEqual(r["tcp_flag_classes_to_victim"], {"syn": 1})
        self.assertEqual(r["udp_top_dst_ports_to_victim"], [])
        self.assertEqual(r["scan"]["non_first_fragments_no_transport_parse"], 2)
        self.assertEqual(r["top_sources_to_victim"], [("172.16.0.5", 3)])

    def test_malformed_ipv4_lengths_are_excluded_from_statistics(self):
        path = Path(self.dir.name) / "bad_len"
        _write_pcap(path, [
            (1.0, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x02), total_length=10)),
            (1.1, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x02))),
        ])
        r = tool.inspect_piece(str(path), "192.168.50.1", None, False)
        self.assertEqual(r["scan"]["malformed_ipv4_excluded"], 1)
        self.assertEqual(r["ipv4_protocols"], {"tcp": 1})
        self.assertEqual(r["tcp_flag_classes_to_victim"], {"syn": 1})
        self.assertEqual(r["top_sources_to_victim"], [("172.16.0.5", 1)])

    def test_partial_record_header_is_reported_as_truncated(self):
        path = Path(self.dir.name) / "partial"
        _write_pcap(path, [(1.0, _ip_packet("172.16.0.5", "192.168.50.1", 6, _tcp(0x02)))])
        with open(path, "ab") as handle:
            handle.write(b"\x01" * 7)  # seven bytes of a next record header
        r = tool.inspect_piece(str(path), None, None, False)
        self.assertEqual(r["scan"]["packets_read"], 1)
        self.assertTrue(r["scan"]["truncated_final_record"])
        self.assertFalse(r["scan"]["reached_end_of_file"])

    def test_rejects_non_pcap_and_does_not_overwrite_output(self):
        bad = Path(self.dir.name) / "bad"
        bad.write_bytes(b"not a pcap at all, definitely")
        with self.assertRaises(ValueError):
            tool.inspect_piece(str(bad), None, None, False)
        out = Path(self.dir.name) / "out.json"
        out.write_text("{}")
        with self.assertRaises(SystemExit):
            tool.main([str(self.path), "--no-hash", "--out", str(out)])
        self.assertEqual(json.loads(out.read_text()), {})


if __name__ == "__main__":
    unittest.main()
