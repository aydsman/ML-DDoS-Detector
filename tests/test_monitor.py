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
    scored = [x for x in lines if x["scored"]]
    assert scored and all(0 <= x["attack_score"] <= 1 for x in scored)
    assert all(x["processing_delay_s"] is None for x in lines)  # replay: no delay claimed
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
