"""Saved synthetic W2 fixtures checked against an independent literal oracle.

No network sockets, VM measurements, public-dataset labels or real attack
activity are involved. LivePipeline replay checks processing, not live capture.
"""
import hashlib
import json
from pathlib import Path

import pytest

from ddos_detector.config import Config, FEATURE_NAMES
from ddos_detector.frames import iter_packets
from ddos_detector.live import LivePipeline
from ddos_detector.normalize import SkipCounter
from ddos_detector.offline import extract_pcap
from ddos_detector.pcap import read_pcap
from tools.create_week2_fixtures import write_fixtures


ROOT = Path(__file__).resolve().parent / "fixtures" / "week2"
ORACLE = json.loads((ROOT / "expected.json").read_text(encoding="utf-8"))
CASES = ORACLE["fixtures"]
CONFIG = Config(victim_ip=ORACLE["victim_ip"], window_seconds=ORACLE["window_seconds"])


def assert_expected_records(records, case):
    assert len(records) == len(case["windows"])
    assert sum(record.packet_count for record in records) == case["selected_packets"]
    assert ORACLE["feature_names"] == FEATURE_NAMES
    for record, expected in zip(records, case["windows"]):
        assert (record.window_start, record.window_end, record.packet_count) == (
            expected["window_start"], expected["window_end"], expected["packet_count"])
        assert list(expected["features"]) == ORACLE["feature_names"]
        assert record.features == pytest.approx(expected["features"], rel=1e-12, abs=1e-12)
        assert record.vector == pytest.approx(
            tuple(expected["features"][name] for name in ORACLE["feature_names"]),
            rel=1e-12, abs=1e-12)
        assert record.capped is False
        assert record.untracked_source_packets == 0


def test_fixture_builder_reproduces_saved_bytes_without_updating_oracle(tmp_path):
    oracle_bytes = (ROOT / "expected.json").read_bytes()
    generated = write_fixtures(tmp_path / "rebuilt")
    assert ORACLE["fixture_kind"] == "synthetic-software-check"
    for case in CASES:
        name = case["filename"]
        saved = (ROOT / name).read_bytes()
        assert hashlib.sha256(saved).hexdigest() == case["sha256"] == generated[name]
        assert (tmp_path / "rebuilt" / name).read_bytes() == saved
    assert (ROOT / "expected.json").read_bytes() == oracle_bytes


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["filename"])
def test_saved_fixture_normalization_matches_literal_packet_ledger(case):
    path = ROOT / case["filename"]
    assert len(list(read_pcap(path))) == case["raw_frames"]
    skips = SkipCounter()
    actual = [[p.ts, p.src, p.proto, p.size, p.flags]
              for p in iter_packets(path, CONFIG.victim_ip, skips)]
    assert actual == case["normalized_packets"]
    assert skips == case["skips"]
    assert len(actual) + sum(skips.values()) == case["raw_frames"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["filename"])
def test_saved_fixture_offline_features_match_literal_arithmetic(case):
    records, skips = extract_pcap(ROOT / case["filename"], CONFIG)
    assert_expected_records(records, case)
    assert skips == case["skips"]


@pytest.mark.parametrize("idle_ticks", [False, True], ids=["frames-only", "with-idle-ticks"])
@pytest.mark.parametrize("case", CASES, ids=lambda case: case["filename"])
def test_saved_fixture_live_replay_matches_same_literal_arithmetic(case, idle_ticks):
    now = [0.0]
    pipeline = LivePipeline(CONFIG, clock=lambda: now[0])

    def source():
        for timestamp, frame in read_pcap(ROOT / case["filename"]):
            now[0] = timestamp
            yield timestamp, frame
            if idle_ticks:
                yield None

    records = list(pipeline.run(source()))
    assert_expected_records(records, case)
    assert pipeline.skips == case["skips"]
    assert pipeline.late_dropped == 0
    assert pipeline.gaps == []
    assert pipeline.status == "ok"
    # This status covers only this successful synthetic replay. There was no
    # network capture whose completeness could be inferred from these results.


def test_gap_is_not_invented_as_a_measured_empty_window():
    case = CASES[0]
    records, _ = extract_pcap(ROOT / case["filename"], CONFIG)
    assert [record.window_start for record in records] == [100.0, 101.0, 103.0]
    assert all(record.packet_count > 0 for record in records)
    # No selected packet was supplied for [102,103). No zero row, healthy
    # coverage claim or benign label may be inferred from its absence.
