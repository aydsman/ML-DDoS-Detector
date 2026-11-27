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


def test_frontend_and_mock_fixture_share_api_origin():
    client = TestClient(api.create_app())
    assert client.get('/frontend/').status_code == 200
    assert 'Data source' in client.get('/frontend/').text
    assert client.get('/frontend/api-client.js').status_code == 200
    assert client.get('/docs/api-examples.json').json()['health']['schema_version'] == '1'


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

    assert api.main(["--audit-log", str(log)]) == 0
    app, options = servers[1]
    assert options["host"] == "127.0.0.1"
    recorded = TestClient(app)
    health = recorded.get("/api/health")
    assert health.headers["X-Dashboard-Freshness"] == "historical"
    assert health.headers["X-Dashboard-Source"] == "recorded_replay"
    assert health.headers["X-Dashboard-Data-Kind"] == "synthetic"
    assert health.json()["capture_status"] == "stopped"
    assert health.json()["mitigation_mode"] == "monitor_only"
    archived_points = recorded.get("/api/metrics").json()["points"]
    assert archived_points == [dict(point, bytes_per_second=None) for point in points]
    assert recorded.get("/api/detections").json()["detections"] == client.get("/api/detections").json()["detections"]
    assert recorded.get("/api/blocks").json()["blocks"] == []


def test_archived_live_failure_preserves_unavailable_state_and_observations():
    records = [status("started"), window(10)[0], dict(status("unavailable"), windows=1)]
    store = api.DashboardStore.from_audit_log(map(json.dumps, records))
    health, headers = store.snapshot("health")
    assert headers["X-Dashboard-Source"] == "recorded_live"
    assert headers["X-Dashboard-Freshness"] == "unavailable"
    assert health["capture_status"] == "error"
    assert store.snapshot("metrics")[0]["points"][0]["packets_per_second"] == 2


def test_archive_rejects_incomplete_mismatched_and_mixed_logs():
    records = [status("started"), window(10)[0]]
    with pytest.raises(ValueError, match="no terminal status"):
        api.DashboardStore.from_audit_log(map(json.dumps, records))
    with pytest.raises(ValueError, match="window count"):
        api.DashboardStore.from_audit_log(map(json.dumps, [*records, dict(status("completed"), windows=2)]))
    bad_window = dict(records[1], model_sha256="other")
    with pytest.raises(ValueError, match="provenance"):
        api.DashboardStore.from_audit_log(map(json.dumps, [records[0], bad_window]))


def test_live_entry_point_serves_events_before_capture_finishes(monkeypatch):
    from threading import Event
    from ddos_detector import monitor
    import uvicorn

    ready = Event()
    finished = Event()
    responses = []

    class FakeServer:
        def __init__(self, config):
            self.config = config
            self.started = False
            self.should_exit = False

        def run(self):
            self.started = True
            ready.set()
            finished.wait(5)

    def capture(arguments, *, deliver):
        assert ready.is_set()
        assert arguments == ["--interface", "enp0s8", "--model", "trusted-model",
                             "--log", "live.jsonl", "--victim", "10.10.10.10", "--duration", "2.0"]
        deliver(status("started"))
        event, record = window(10)
        deliver(event, record)
        response = client.get("/api/metrics")
        responses.append(response.json())
        assert response.headers["X-Dashboard-Source"] == "live"
        assert response.headers["X-Dashboard-Freshness"] == "current"
        deliver(status("completed"))
        finished.set()
        return 0

    store = api.DashboardStore(clock=lambda: 11)
    client = TestClient(api.create_app(store))
    monkeypatch.setattr(api, "DashboardStore", lambda: store)
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setattr(monitor, "main", capture)
    assert api.main(["--interface", "enp0s8", "--model", "trusted-model", "--log", "live.jsonl",
                     "--victim", "10.10.10.10", "--duration", "2"]) == 0
    assert responses[0]["points"][0]["packets_per_second"] == 2
    assert client.get("/api/health").headers["X-Dashboard-Freshness"] == "stopped"


def test_live_server_bind_failure_prevents_capture(monkeypatch):
    from ddos_detector import monitor
    import uvicorn

    class FailedServer:
        def __init__(self, config):
            self.started = False
            self.should_exit = False

        def run(self):
            raise SystemExit(1)

    monkeypatch.setattr(uvicorn, "Server", FailedServer)
    monkeypatch.setattr(monitor, "main", lambda *a, **kw: pytest.fail("Capture must not start"))
    assert api.main(["--interface", "enp0s8", "--model", "model", "--log", "live.jsonl"]) == 2


@pytest.mark.parametrize("arguments", [
    ["--interface", "enp0s8"],
    ["--replay", "capture.pcap", "--duration", "2"],
    ["--interface", "enp0s8", "--duration", "nan"],
])
def test_live_entry_point_rejects_incompatible_options(arguments):
    with pytest.raises(SystemExit) as error:
        api.main(arguments)
    assert error.value.code == 2


def test_capture_startup_failure_delivers_unavailable_without_started(tmp_path, model_dir, monkeypatch):
    from ddos_detector import capture, monitor

    def unavailable(*args, **kwargs):
        raise PermissionError("test capture cannot open")

    monkeypatch.setattr(capture, "capture_frames", unavailable)
    store = api.DashboardStore()
    log = tmp_path / "capture-unavailable.jsonl"
    assert monitor.main(["--interface", "enp0s8", "--model", str(model_dir),
                         "--log", str(log)], deliver=store.ingest) == 2
    health, headers = store.snapshot("health")
    assert health["capture_status"] == "error"
    assert headers["X-Dashboard-Freshness"] == "unavailable"
    assert store.snapshot("metrics")[0]["points"] == []
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [row["status"] for row in rows] == ["unavailable"]
    archived = api.DashboardStore.from_audit_log(map(json.dumps, rows))
    assert archived.snapshot("health")[1]["X-Dashboard-Freshness"] == "unavailable"
