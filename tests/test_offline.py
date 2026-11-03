import csv
import json
from pathlib import Path

import pytest

from ddos_detector.config import FEATURE_NAMES, Config
from ddos_detector.offline import COLUMNS, extract_pcap, main
from test_frames import eth, ipv4
from test_pcap import build_pcap
from tools import verify_pcap_features as verify

VICTIM = "10.10.10.10"
LAB_DIR = Path(__file__).resolve().parent.parent / "data/lab-runs"
LAB_PCAPS = sorted(LAB_DIR.glob("*/*.pcap"))
TSHARK = verify.find_tshark()


def synthetic_pcap(tmp_path):
    frames = [
        (100.2, eth(0x0800, ipv4(src="10.10.10.30", flags=0x02))),
        (100.999999, eth(0x0800, ipv4(src="10.10.10.31", flags=0x12))),
        (101.0, eth(0x0800, ipv4(src="10.10.10.30", proto=17, total_length=60))),
        (101.5, eth(0x0806, bytes(28))),
        (101.6, eth(0x0800, ipv4(dst="10.10.10.99"))),
        (104.3, eth(0x0800, ipv4(src="10.10.10.32", proto=1, total_length=84))),
    ]
    return build_pcap(tmp_path / "s.pcap", records=frames)


def test_extract_pcap_windows_and_skips(tmp_path):
    records, skips = extract_pcap(synthetic_pcap(tmp_path), Config())
    assert [(r.window_start, r.packet_count) for r in records] == [(100.0, 2), (101.0, 1), (104.0, 1)]
    assert skips == {"non_ip": 1, "not_inbound": 1}
    assert records[0].features["syn_count"] == 1


def test_extract_pcap_is_deterministic(tmp_path):
    path = synthetic_pcap(tmp_path)
    assert extract_pcap(path) == extract_pcap(path)


def test_cli_csv_output_and_summary(tmp_path, capsys):
    out = tmp_path / "r.csv"
    assert main([str(synthetic_pcap(tmp_path)), "--out", str(out)]) == 0
    summary = capsys.readouterr().out
    assert "windows: 3" in summary and "packets: 4" in summary
    assert "non_ip=1" in summary and "not_inbound=1" in summary and "late_dropped: 0" in summary
    with open(out, newline="") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0]) == COLUMNS == ["window_start", "window_end", *FEATURE_NAMES,
                                        "packet_count", "capped", "untracked_source_packets"]
    assert [float(r["window_start"]) for r in rows] == [100.0, 101.0, 104.0]
    assert rows[0]["capped"] == "False" and rows[0]["packet_count"] == "2"


def test_cli_jsonl_output(tmp_path):
    out = tmp_path / "r.jsonl"
    assert main([str(synthetic_pcap(tmp_path)), "--out", str(out)]) == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 3 and list(rows[0]) == COLUMNS
    assert rows[0]["packet_rate"] == 2.0 and rows[0]["capped"] is False


def test_cli_writes_nothing_without_out(tmp_path, capsys):
    path = synthetic_pcap(tmp_path)
    before = set(tmp_path.iterdir())
    assert main([str(path)]) == 0
    assert set(tmp_path.iterdir()) == before


def test_cli_victim_and_window_options(tmp_path, capsys):
    assert main([str(synthetic_pcap(tmp_path)), "--victim", "10.10.10.99", "--window", "10"]) == 0
    assert "windows: 1" in capsys.readouterr().out


def test_cli_pcap_error_exits_2(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00" * 40)
    assert main([str(bad)]) == 2
    assert "bad magic" in capsys.readouterr().err
    assert main([str(tmp_path / "missing.pcap")]) == 2


def test_cli_rejects_unknown_output_extension(tmp_path):
    with pytest.raises(SystemExit):
        main([str(synthetic_pcap(tmp_path)), "--out", str(tmp_path / "r.txt")])


def assert_agrees(result):
    assert result["problems"] == []
    assert max(result["max_rel"].values()) <= 1e-9


def test_synthetic_matches_scapy_reference(tmp_path):
    path = synthetic_pcap(tmp_path)
    assert_agrees(verify.compare(path, verify.scapy_rows(str(path), VICTIM)))


@pytest.mark.skipif(TSHARK is None, reason="tshark not found")
def test_synthetic_matches_tshark_reference(tmp_path):
    path = synthetic_pcap(tmp_path)
    assert_agrees(verify.compare(path, verify.tshark_rows(str(path), VICTIM, TSHARK)))


@pytest.mark.parametrize("pcap", LAB_PCAPS, ids=lambda p: p.name)
def test_lab_pcap_matches_scapy_reference(pcap):
    assert_agrees(verify.compare(pcap, verify.scapy_rows(str(pcap), VICTIM)))


@pytest.mark.skipif(TSHARK is None, reason="tshark not found")
@pytest.mark.parametrize("pcap", LAB_PCAPS, ids=lambda p: p.name)
def test_lab_pcap_matches_tshark_reference(pcap):
    assert_agrees(verify.compare(pcap, verify.tshark_rows(str(pcap), VICTIM, TSHARK)))
