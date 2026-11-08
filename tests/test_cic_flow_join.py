import contextlib
import csv
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

import pytest

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

# Independent byte fixtures for the four PR #29 review findings. Never transmitted.
@pytest.mark.parametrize('endian', ['<', '>'])
@pytest.mark.parametrize('scale,magic,frac,want', [
    (1_000_000, 0xA1B2C3D4, 123456, 100123456),
    (1_000_000_000, 0xA1B23C4D, 123456000, 100123456),
    (1_000_000_000, 0xA1B23C4D, 999999999, 100999999),
    (1_000_000_000, 0xA1B23C4D, 999, 100000000),
])
def test_timestamp_resolution_and_byte_order(tmp_path, endian, scale, magic, frac, want):
    packet = ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80))
    path = tmp_path / 'precision.pcap'
    with path.open('wb') as f:
        f.write(struct.pack(endian + 'IHHiIII', magic, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack(endian + 'IIII', 100, frac, len(packet), len(packet)))
        f.write(packet)
    rows = list(join.iter_packets(path))
    assert rows == [(want, packet)]
    assert rows[0][0] // 1_000_000 == 100
    # The production extractor and integer labelling pass assign the same second.
    assert [int(r.window_start) for r in join.extract_chain([path], join.Config(victim_ip=VICTIM))] == [100]


@pytest.mark.parametrize('change', ['version', 'ihl', 'total_length', 'short_options', 'fragment', 'padding'])
def test_invalid_or_unreadable_packets_cannot_support_offset(tmp_path, change):
    packet = bytearray(ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80)))
    if change == 'version': packet[14] = 0x65
    elif change == 'ihl': packet[14] = 0x44
    elif change == 'total_length': packet[16:18] = struct.pack('!H', 10)
    elif change == 'short_options': packet[14] = 0x4F
    elif change == 'fragment': packet[20:22] = struct.pack('!H', 1)
    elif change == 'padding': packet[16:18] = struct.pack('!H', 20)
    path = tmp_path / 'rejected.pcap'
    write_pcap(path, [(100_000_000, bytes(packet))])
    flows = [flow((ATTACKER, 1000, VICTIM, 80, 6), 100_000_000, 100, 'Syn')]
    assert join.offset_test(flows, [path], [0], VICTIM) == {0: 0}
    stats, _ = join.label_windows(flows, [path], VICTIM, {'Syn'}, 0)
    assert sum(c['attack'] for c in stats.values()) == 0


def test_offset_search_explicitly_retains_other_valid_destinations(tmp_path):
    other = '192.168.50.9'
    path = tmp_path / 'other.pcap'
    write_pcap(path, [(100_000_000, ip_frame(ATTACKER, other, 6, tcp(1000, 80)))])
    flows = [flow((ATTACKER, 1000, other, 80, 6), 100_000_000, 100, 'Syn')]
    assert join.offset_test(flows, [path], [0], VICTIM) == {0: 1}
    assert not join.label_windows(flows, [path], VICTIM, {'Syn'}, 0)[0]


def run_synthetic_join(tmp_path, records, flows):
    path, csv_path, out = tmp_path / 'piece.pcap', tmp_path / 'flows.csv', tmp_path / 'output'
    write_pcap(path, [(ts, ip_frame(ATTACKER, VICTIM, 6, tcp(port, 80))) for ts, port in records])
    with csv_path.open('w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Flow Duration', 'Label', 'Source IP', 'Source Port',
                         'Destination IP', 'Destination Port', 'Protocol'])
        for start, duration in flows:
            writer.writerow([start, duration, 'Syn', ATTACKER, 1000, VICTIM, 80, 6])
    with contextlib.redirect_stdout(io.StringIO()):
        join.main(['--csv', str(csv_path), '--pieces', str(path), '--victim', VICTIM,
                   '--attack-label', 'Syn', '--offset-hours', '0', '--run-id', 'synthetic-review',
                   '--out-dir', str(out)])
    return out, {int(r['window_start']): r for r in json.loads((out / 'windows.json').read_text())}


def test_onset_and_ending_boundaries_excluded_but_interior_flow_starts_are_not(tmp_path):
    records = [(100_000_000, 2000), (101_200_000, 1000), (101_800_000, 1000),
               (102_100_000, 1000), (102_300_000, 1000), (103_100_000, 1000),
               (104_100_000, 1000), (105_000_000, 2000)]
    out, rows = run_synthetic_join(tmp_path, records, [
        ('1970-01-01 00:01:41.200000', 3_000_000),
        ('1970-01-01 00:01:42.300000', 1_000_000)])
    for second in (101, 104):
        assert rows[second]['boundary'] is True
        assert rows[second]['inside_attack_interval'] is False
        assert rows[second]['label'] == 'excluded'
    for second in (102, 103):
        assert rows[second]['boundary'] is False
        assert rows[second]['label'] == 'attack'
    manifest = json.loads((out / 'manifest.json').read_text())
    assert manifest['data_kind'] == 'candidate_unreviewed_packet_windows'
    assert all(v is None for v in manifest['review_refs'].values())
    assert manifest['runs']['synthetic-review']['split'] is None
    from ddos_detector.training_data import prepare_data
    with pytest.raises(ValueError, match='data_kind'):
        prepare_data(out / 'windows.json', out / 'manifest.json')


def test_closed_interval_ending_on_axis_cannot_promote_following_window(tmp_path):
    _, rows = run_synthetic_join(tmp_path, [(100_000_000, 2000), (101_000_000, 1000),
        (102_000_000, 1000), (103_000_000, 1000), (104_000_000, 2000)],
        [('1970-01-01 00:01:41', 2_000_000)])
    assert rows[101]['label'] == rows[102]['label'] == 'attack'
    assert rows[103]['boundary'] is True and rows[103]['label'] == 'excluded'


@pytest.mark.parametrize('names', [('piece.pcap', 'piece.pcap'), ('PIECE.pcap', 'piece.pcap')])
def test_duplicate_capture_ids_fail_before_input_reads_or_output(tmp_path, names):
    out = tmp_path / 'output'
    # Files deliberately absent: collision must be detected before attempting the CSV/PCAP.
    with pytest.raises(SystemExit) as e:
        join.main(['--csv', str(tmp_path / 'absent.csv'), '--pieces',
                   str(tmp_path / 'a' / names[0]), str(tmp_path / 'b' / names[1]),
                   '--victim', VICTIM, '--attack-label', 'Syn', '--offset-hours', '0',
                   '--run-id', 'synthetic-review', '--out-dir', str(out)])
    assert e.value.code == 2
    assert not out.exists()


@pytest.mark.parametrize('damage', ['record_header', 'payload', 'bad_fraction', 'non_ethernet'])
def test_corrupt_or_unsupported_pcap_fails_explicitly(tmp_path, damage):
    path = tmp_path / 'damaged.pcap'
    packet = ip_frame(ATTACKER, VICTIM, 6, tcp(1000, 80))
    raw = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 2 if damage == 'non_ethernet' else 1)
    if damage == 'record_header': raw += b'1234567'
    else:
        raw += struct.pack('<IIII', 100, 1_000_000 if damage == 'bad_fraction' else 0, len(packet), len(packet))
        raw += packet[:-1] if damage == 'payload' else packet
    path.write_bytes(raw)
    with pytest.raises(ValueError): list(join.iter_packets(path))
