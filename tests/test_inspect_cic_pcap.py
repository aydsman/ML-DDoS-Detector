import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools import inspect_cic_pcap as tool


def _ip_packet(src, dst, proto, l4):
    total = 20 + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
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
