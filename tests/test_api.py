import json

from fastapi.testclient import TestClient
import pytest

from ddos_detector import api
from ddos_detector.aggregate import WindowRecord
from ddos_detector.config import FEATURE_NAMES
from test_monitor import model_dir, pcap


def status(state, source="live"):
    return {"record_type": "monitor_status", "monitor_only": True, "logged_at": 10,
            "status": state, "source_mode": source, "data_kind": "synthetic", "model_sha256": "demo"}


def window(start, *, capped=False):
    features = dict.fromkeys(FEATURE_NAMES, 0.0)
    features.update(packet_rate=2.0, byte_rate=120.0)
    record = WindowRecord(start, start + 1, tuple(features.values()), 2, capped=capped)
    event = {"record_type": "window", "monitor_only": True, "logged_at": start + 1,
             "window_start": start, "window_end": start + 1, "packet_count": 2,
             "scored": not capped, "attack_score": 0.8, "decision_threshold": 0.5,
             "predicted_attack": True, "scoring_s": 0.001, "data_kind": "synthetic",
             "model_sha256": "demo"}
    return event, record


def test_empty_store_exposes_read_only_contract():
    client = TestClient(api.create_app())
    for section, expected in (
        ("metrics", {"points": []}), ("detections", {"detections": []}), ("blocks", {"blocks": []}),
        ("health", {"capture_status": "stopped", "model_status": "loading",
                    "firewall_status": "unavailable", "mitigation_mode": "monitor_only"}),
    ):
        response = client.get(f"/api/{section}")
        payload = response.json()
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Dashboard-Freshness"] == "empty"
        assert payload.pop("updated_at").endswith("Z")
        assert payload == {"schema_version": "1", **expected}
        assert client.post(f"/api/{section}", json={}).status_code == 405


def test_live_freshness_failure_and_bounded_history():
    now = [14]
    store = api.DashboardStore(history_limit=2, clock=lambda: now[0])
    client = TestClient(api.create_app(store))
    store.ingest(status("started"))
    assert client.get("/api/health").json()["capture_status"] == "stopped"
    for start in (10, 11, 13):
        store.ingest(*window(start, capped=start == 13))
    health = client.get("/api/health")
    assert health.json()["capture_status"] == "running"
    assert health.headers["X-Dashboard-Freshness"] == "current"
    points = client.get("/api/metrics").json()["points"]
    assert [p["window_start"] for p in points] == [api.utc_timestamp(t) for t in (11, 13)]
    assert all(p["bytes_per_second"] == 120 for p in points)
    detections = client.get("/api/detections").json()["detections"]
    assert [d["id"] for d in detections] == ["aggregate-11", "aggregate-10"]
    assert all(d["decision"] == "alert" and d["source_ip"] is None for d in detections)
    assert client.get("/api/blocks").json()["blocks"] == []

    now[0] = 21
    health = client.get("/api/health")
    assert health.headers["X-Dashboard-Freshness"] == "stale"
    assert health.json()["capture_status"] == "error"
    store.ingest(dict(status("unavailable"), logged_at=now[0]))
    assert client.get("/api/health").headers["X-Dashboard-Freshness"] == "unavailable"
    assert client.get("/api/metrics").json()["points"] == points
    assert client.get("/api/detections").json()["detections"] == detections


def test_invalid_delivery_leaves_state_unchanged():
    store = api.DashboardStore()
    store.ingest(status("started"))
    event, record = window(10)
    with pytest.raises(ValueError, match="score"):
        store.ingest(dict(event, attack_score=float("nan")), record)
    assert store.snapshot("metrics")[0]["points"] == []
    store.ingest(event, record)
    with pytest.raises(ValueError, match="ordered"):
        store.ingest(event, record)
    with pytest.raises(ValueError, match="lifecycle"):
        store.ingest(status("completed", source="replay"))
    assert len(store.snapshot("detections")[0]["detections"]) == 1


def test_replay_cli_feeds_actual_monitor_events_to_api(tmp_path, model_dir, monkeypatch):
    import uvicorn

    servers = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: servers.append((app, options)))
    log = tmp_path / "monitor.jsonl"
    assert api.main(["--replay", str(pcap(tmp_path)), "--model", str(model_dir), "--log", str(log)]) == 0
    app, options = servers[0]
    assert options["host"] == "127.0.0.1"
    client = TestClient(app)
    health = client.get("/api/health")
    assert health.headers["X-Dashboard-Freshness"] == "historical"
    assert health.headers["X-Dashboard-Source"] == "replay"
    assert health.headers["X-Dashboard-Data-Kind"] == "synthetic"
    assert health.json()["capture_status"] == "stopped"
    assert health.json()["model_status"] == "loaded"
    events = [json.loads(line) for line in log.read_text().splitlines()]
    windows = [e for e in events if e["record_type"] == "window"]
    points = client.get("/api/metrics").json()["points"]
    assert points and [p["packets_per_second"] for p in points] == [e["packet_count"] for e in windows]
    scores = [e["attack_score"] for e in windows if e["scored"]]
    assert sorted(d["attack_score"] for d in client.get("/api/detections").json()["detections"]) == sorted(scores)
    assert events[-1]["status"] == "completed"
