import struct
import tempfile
import unittest
from pathlib import Path

from tools import cic_flow_join as join

VICTIM = "192.168.50.1"
ATTACKER = "172.16.0.5"
HOUR = join.HOUR_US


def ip_frame(src, dst, proto, l4, frag=0, total_length=None):
    total = total_length if total_length is not None else 20 + len(l4)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, frag, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\x00" * 12 + b"\x08\x00" + header + l4


def tcp(sport, dport, flags=0x02):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 0, 0, 0)


def write_pcap(path, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts_us, data in packets:
            handle.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000,
                                     len(data), len(data)))
            handle.write(data)


def flow(key, start_csv_us, duration_us, label):
    return {"start": start_csv_us, "end": start_csv_us + duration_us, "label": label, "key": key}


class CicFlowJoinTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.pcap = str(Path(self.dir.name) / "piece")
        self.t0 = 1_543_685_430_000_000  # pcap epoch microseconds
        self.csv0 = self.t0 - 4 * HOUR   # CSV local time is 4 hours behind
        write_pcap(self.pcap, [
            (self.t0, ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80))),
            (self.t0 + 10, ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80))),
            (self.t0 + 500, ip_frame(ATTACKER, VICTIM, 6, tcp(2000, 80))),       # no flow
            (self.t0 + 600, ip_frame(ATTACKER, VICTIM, 1, b"\x08\x00" + b"\x00" * 6)),
            (self.t0 + 700, ip_frame(ATTACKER, VICTIM, 17, b"\x00" * 8, frag=1)),
            (self.t0 + 800, ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80), total_length=10)),
            (self.t0 + 900, ip_frame(ATTACKER, "192.168.50.9", 6, tcp(1000, 80))),
        ])
        self.flows = [flow((ATTACKER, 1000, VICTIM, 80, 6), self.csv0, 100, "Syn"),
                      flow((ATTACKER, 0, VICTIM, 0, 0), self.csv0 + 550, 100, "Syn")]

    def tearDown(self):
        self.dir.cleanup()

    def test_csv_timestamp_to_integer_microseconds(self):
        self.assertEqual(join.csv_us("2018-12-01 13:30:30.741451"),
                         join.csv_us("2018-12-01 13:30:30.741451000"))
        self.assertEqual(join.csv_us("1970-01-01 00:00:01.5"), 1_500_000)
        self.assertEqual(join.csv_us("1970-01-01 00:00:02"), 2_000_000)

    def test_offset_is_found_only_at_the_true_hour(self):
        found = join.offset_test(self.flows[:1], [self.pcap], [-4, 0, 4], VICTIM)
        self.assertEqual(found, {-4: 0, 0: 0, 4: 1})

    def test_packet_scope_rejects_malformed_other_destination_and_fragments_ports(self):
        frames = dict(enumerate(d for _, d in join.iter_packets(self.pcap)))
        self.assertEqual(join.packet_scope(frames[0], VICTIM), (ATTACKER, 1000, VICTIM, 80, 6))
        self.assertEqual(join.packet_scope(frames[4], VICTIM)[1], None)  # non-first fragment
        self.assertIsNone(join.packet_scope(frames[5], VICTIM))          # Total Length 10
        self.assertIsNone(join.packet_scope(frames[6], VICTIM))          # other destination

    def test_labelling_counts_and_icmp_is_opt_in(self):
        off = 4 * HOUR
        stats, reasons = join.label_windows(self.flows, [self.pcap], VICTIM, {"Syn"}, off)
        s = stats[self.t0 // 1_000_000]
        self.assertEqual((s["selected"], s["attack"], s["unknown"]), (5, 2, 3))
        self.assertEqual(reasons["no_matching_flow_interval"], 1)
        self.assertEqual(reasons["no_5_tuple(icmp_or_non_first_fragment_or_short)"], 2)
        stats, _ = join.label_windows(self.flows, [self.pcap], VICTIM, {"Syn"}, off,
                                      icmp_as_protocol0=True)
        s = stats[self.t0 // 1_000_000]
        self.assertEqual((s["attack"], s["unknown"]), (3, 2))

    def test_csv_benign_and_ambiguous_flows_are_unknown(self):
        off = 4 * HOUR
        benign = [flow((ATTACKER, 1000, VICTIM, 80, 6), self.csv0, 100, "BENIGN")]
        stats, reasons = join.label_windows(benign, [self.pcap], VICTIM, {"Syn"}, off)
        self.assertEqual(stats[self.t0 // 1_000_000]["attack"], 0)
        self.assertEqual(reasons["matched_csv_label_BENIGN_not_independently_verified"], 2)
        both = [flow((ATTACKER, 1000, VICTIM, 80, 6), self.csv0, 100, "Syn"),
                flow((ATTACKER, 1000, VICTIM, 80, 6), self.csv0, 100, "BENIGN")]
        _, reasons = join.label_windows(both, [self.pcap], VICTIM, {"Syn"}, off)
        self.assertEqual(reasons["ambiguous_labels"], 2)

    def test_padding_beyond_ip_total_length_is_not_read_as_ports(self):
        padded = ip_frame(ATTACKER, VICTIM, 6, b"") + bytes([0x03, 0xE8, 0x00, 0x50]) + bytes(16)
        path = str(Path(self.dir.name) / "padded")
        write_pcap(path, [(self.t0, padded)])
        data = next(d for _, d in join.iter_packets(path))
        self.assertEqual(join.packet_scope(data, VICTIM), (ATTACKER, None, VICTIM, None, 6))
        # the offset test must not match a flow whose ports only exist in the padding
        flows = [flow((ATTACKER, 1000, VICTIM, 80, 6), self.csv0, 100, "Syn")]
        self.assertEqual(join.offset_test(flows, [path], [4], VICTIM), {4: 0})

    def test_reverse_direction_packets_match_the_initiators_flow(self):
        off = 4 * HOUR
        reverse = [flow((VICTIM, 80, ATTACKER, 1000, 6), self.csv0, 100, "Syn")]
        stats, _ = join.label_windows(reverse, [self.pcap], VICTIM, {"Syn"}, off)
        self.assertEqual(stats[self.t0 // 1_000_000]["attack"], 2)


if __name__ == "__main__":
    unittest.main()
