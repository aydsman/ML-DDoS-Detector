import json
import random
import sys
from pathlib import Path

import pytest

from ddos_detector.monitor import Monitor, main
from ddos_detector.aggregate import WindowRecord
from ddos_detector.config import FEATURE_NAMES
from test_frames import eth, ipv4
from test_pcap import build_pcap

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
pytest.importorskip("sklearn")


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory):
    from tools.create_training_demo import create_demo
    from ddos_detector import training
    base = tmp_path_factory.mktemp("demo")
    data = base / "input"
    create_demo(data)
    model = base / "model"
    assert training.main(["train", "--records", str(data / "records.json"),
                          "--manifest", str(data / "manifest.json"),
                          "--allow-synthetic", "--output", str(model)]) in (0, None)
    return model


def pcap(tmp_path, n=400, seed=5):
    rng = random.Random(seed)
    frames = []
    for ts in sorted(rng.uniform(100, 106) for _ in range(n)):
        frames.append((ts, eth(0x0800, ipv4(src=f"10.10.10.{rng.randrange(20, 40)}", flags=rng.choice([0x02, 0x10])))))
    return build_pcap(tmp_path / "m.pcap", records=frames)


def test_replay_logs_one_line_per_window_and_never_blocks(tmp_path, model_dir):
    log = tmp_path / "pred.jsonl"
    assert main(["--replay", str(pcap(tmp_path)), "--model", str(model_dir), "--log", str(log)]) == 0
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert lines and all(x["monitor_only"] is True for x in lines)
    windows = [x for x in lines if x["record_type"] == "window"]
    scored = [x for x in windows if x["scored"]]
    assert scored and all(0 <= x["attack_score"] <= 1 for x in scored)
    assert all(x["processing_delay_s"] is None for x in windows)  # replay: no delay claimed
    assert all(x["data_kind"] == "synthetic" for x in scored)


def test_existing_log_is_not_overwritten(tmp_path, model_dir):
    log = tmp_path / "pred.jsonl"
    log.write_text("keep")
    assert main(["--replay", str(pcap(tmp_path)), "--model", str(model_dir), "--log", str(log)]) == 2
    assert log.read_text() == "keep"


def test_bad_model_stops_before_logging(tmp_path):
    log = tmp_path / "pred.jsonl"
    assert main(["--replay", str(pcap(tmp_path)), "--model", str(tmp_path / "nope"), "--log", str(log)]) == 2
    assert not log.exists()


def test_capped_window_is_logged_not_scored(tmp_path, model_dir):
    log = (tmp_path / "x.jsonl").open("x")
    rec = WindowRecord(10.0, 11.0, tuple(1.0 for _ in FEATURE_NAMES), 5, capped=True)
    mon = Monitor(str(model_dir), log, 1.0)
    mon.handle(rec)
    log.close()
    line = json.loads((tmp_path / "x.jsonl").read_text())
    assert line["scored"] is False and "capped" in line["not_scored_reason"].lower()
    assert "attack_score" not in line and mon.not_scored == 1


def test_live_delay_is_measured_from_window_end(tmp_path, model_dir):
    log = (tmp_path / "y.jsonl").open("x")
    rec = WindowRecord(10.0, 11.0, tuple(1.0 for _ in FEATURE_NAMES), 5)
    mon = Monitor(str(model_dir), log, 1.0, clock=lambda: 12.5, live=True)
    mon.handle(rec)
    log.close()
    assert json.loads((tmp_path / "y.jsonl").read_text())["processing_delay_s"] == 1.5

@pytest.mark.parametrize('window', ['2', '0', '-1', 'nan', 'inf'])
def test_incompatible_window_rejected_before_log(tmp_path, window):
    log = tmp_path / 'never.jsonl'
    with pytest.raises(SystemExit) as exc:
        main(['--replay', 'unused.pcap', '--model', 'unused-model', '--log', str(log), '--window', window])
    assert exc.value.code == 2 and not log.exists()


@pytest.mark.parametrize('duration', ['0', '-1', 'nan', 'inf'])
def test_invalid_duration_rejected_before_log(tmp_path, duration):
    log = tmp_path / 'never.jsonl'
    with pytest.raises(SystemExit):
        main(['--replay', 'unused.pcap', '--model', 'unused-model', '--log', str(log), '--duration', duration])
    assert not log.exists()


def test_model_is_loaded_once_for_entire_run(tmp_path, model_dir, monkeypatch):
    from ddos_detector import monitor
    real_load = monitor.load_model
    calls = []
    def tracked(path):
        calls.append(path)
        return real_load(path)
    monkeypatch.setattr(monitor, 'load_model', tracked)
    log = tmp_path / 'cached.jsonl'
    assert main(['--replay', str(pcap(tmp_path)), '--model', str(model_dir), '--log', str(log)]) == 0
    assert len(calls) == 1
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows[0]['status'] == 'started' and rows[-1]['status'] == 'completed'
    assert rows[-1]['data_kind'] == 'synthetic'
    assert rows[-1]['backlog'] is None and rows[-1]['kernel_drops'] is None
    assert rows[-1]['windows'] == sum(r['record_type'] == 'window' for r in rows)


def test_capture_failure_is_retained_in_audit_log(tmp_path, model_dir, monkeypatch):
    from ddos_detector import monitor
    def broken(_):
        yield 100.1, eth(0x0800, ipv4())
        raise OSError('synthetic read failure')
    monkeypatch.setattr(monitor, 'read_pcap', broken)
    log = tmp_path / 'failure.jsonl'
    assert main(['--replay', 'synthetic-only', '--model', str(model_dir), '--log', str(log)]) == 1
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert not any(r['record_type'] == 'window' for r in rows)
    assert rows[-1]['status'] == 'unavailable'
    assert 'synthetic read failure' in rows[-1]['gaps'][0]['reason']
    assert rows[-1]['gaps'][0]['discarded_windows'] == 1


def test_damaged_replay_has_failure_event_and_nonzero_exit(tmp_path, model_dir):
    path, log = tmp_path / 'bad.pcap', tmp_path / 'damaged.jsonl'
    path.write_bytes(b'not a pcap')
    assert main(['--replay', str(path), '--model', str(model_dir), '--log', str(log)]) == 2
    rows = [json.loads(x) for x in log.read_text().splitlines()]
    assert rows[-1]['status'] == 'unavailable'
    assert rows[-1]['gaps'] and 'PcapError' in rows[-1]['gaps'][0]['reason']
