"""Read-only dashboard API and bounded monitor state."""
import argparse
from collections import deque
from datetime import datetime, timezone
import math
from threading import Lock
import time
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles


def utc_timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Expected finite epoch seconds")
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError("Timestamp outside supported UTC range") from exc


class DashboardStore:
    """Hold recent observations from one monitor run per server process."""

    def __init__(self, history_limit=300, stale_after=5.0, clock=time.time):
        if type(history_limit) is not int or not 1 <= history_limit <= 3600:
            raise ValueError("history_limit must be an integer between 1 and 3600")
        if type(stale_after) not in (int, float) or not math.isfinite(stale_after) or stale_after <= 0:
            raise ValueError("stale_after must be finite and positive")
        self._points = deque(maxlen=history_limit)
        self._detections = deque(maxlen=history_limit)
        self._clock = clock
        self._stale_after = stale_after
        self._lock = Lock()
        self._state = "idle"
        self._source = "none"
        self._data_kind = "none"
        self._model = None
        self._last_window_end = None
        self._started_at = None

    def ingest(self, event, record=None):
        """Receive typed monitor output and its original window, if applicable."""
        if event.get("monitor_only") is not True:
            raise ValueError("Expected a monitor-only event")
        utc_timestamp(event["logged_at"])
        with self._lock:
            kind = event.get("record_type")
            if kind == "monitor_status" and record is None:
                self._ingest_status(event)
            elif kind == "window" and record is not None:
                self._ingest_window(event, record)
            else:
                raise ValueError("Unsupported monitor event")

    def _ingest_status(self, event):
        state = event["status"]
        source = event["source_mode"]
        data_kind = event["data_kind"]
        model = event["model_sha256"]
        if source not in ("replay", "live") or data_kind not in ("synthetic", "reviewed_packet_windows"):
            raise ValueError("Invalid monitor provenance")
        if not isinstance(model, str) or not model:
            raise ValueError("Missing model identity")
        if state == "started" and self._state == "idle":
            self._source, self._data_kind, self._model = source, data_kind, model
            self._started_at = event["logged_at"]
        elif (self._state != "started" or state not in ("completed", "unavailable")
              or (source, data_kind, model) != (self._source, self._data_kind, self._model)):
            raise ValueError("Unexpected monitor lifecycle transition")
        self._state = state

    def _ingest_window(self, event, record):
        start, end = record.window_start, record.window_end
        timestamp = utc_timestamp(start)
        utc_timestamp(end)
        if (self._state != "started" or end - start != 1 or start % 1
                or event["window_start"] != start or event["window_end"] != end
                or event["packet_count"] != record.packet_count
                or self._last_window_end is not None and start < self._last_window_end):
            raise ValueError("Expected an ordered finalized one-second monitor window")
        rates = {key: record.features[name] for key, name in (
            ("packets_per_second", "packet_rate"), ("bytes_per_second", "byte_rate"))}
        if any(type(value) not in (int, float) or not math.isfinite(value) or value < 0
               for value in rates.values()):
            raise ValueError("Invalid window rate")
        if type(record.packet_count) is not int or record.packet_count != rates["packets_per_second"]:
            raise ValueError("Window rate and packet count disagree")
        scored = event["scored"]
        if type(scored) is not bool:
            raise ValueError("Invalid scoring status")
        detection = None
        if scored:
            score = event["attack_score"]
            threshold = event["decision_threshold"]
            if (record.capped or not record.packet_count
                    or event["model_sha256"] != self._model or event["data_kind"] != self._data_kind
                    or any(type(value) not in (int, float) or not 0 <= value <= 1
                           for value in (score, threshold))
                    or event["predicted_attack"] is not (score >= threshold)):
                raise ValueError("Invalid aggregate score or provenance")
            scoring_time = event["scoring_s"]
            if type(scoring_time) not in (int, float) or not math.isfinite(scoring_time) or scoring_time < 0:
                raise ValueError("Invalid scoring duration")
            detection = {
                "id": f"aggregate-{int(start)}",
                "detected_at": utc_timestamp(event["logged_at"] + scoring_time),
                "scope": "aggregate", "source_ip": None, "attack_score": score,
                "model_version": self._model, "aggregate_detection_id": None, "attribution": None,
                "decision": "alert" if event["predicted_attack"] else "no_action",
            }
        self._points.append({"window_start": timestamp, "window_seconds": 1, **rates})
        if detection is not None:
            self._detections.append(detection)
        self._last_window_end = end

    def snapshot(self, section):
        with self._lock:
            now = self._clock()
            freshness = self._freshness(now)
            if section == "health":
                capture = "stopped"
                if freshness in ("unavailable", "stale"):
                    capture = "error"
                elif self._source == "live" and freshness == "current":
                    capture = "running"
                data = {"capture_status": capture, "model_status": "loading" if self._model is None else "loaded",
                        "firewall_status": "unavailable", "mitigation_mode": "monitor_only"}
            elif section == "metrics":
                data = {"points": [point.copy() for point in self._points]}
            elif section == "detections":
                rows = sorted(self._detections, key=lambda row: (
                    -datetime.fromisoformat(row["detected_at"]).timestamp(), row["id"]))
                data = {"detections": [row.copy() for row in rows]}
            elif section == "blocks":
                data = {"blocks": []}
            else:
                raise ValueError("Unknown dashboard section")
            headers = {"Cache-Control": "no-store", "X-Dashboard-Freshness": freshness,
                       "X-Dashboard-Source": self._source, "X-Dashboard-Data-Kind": self._data_kind}
            return {"schema_version": "1", "updated_at": utc_timestamp(now), **data}, headers

    def _freshness(self, now):
        if self._state == "unavailable":
            return "unavailable"
        if self._source == "replay":
            return "historical"
        if self._state == "started":
            last = self._last_window_end if self._last_window_end is not None else self._started_at
            if now - last > self._stale_after:
                return "stale"
            if self._last_window_end is not None:
                return "current"
        return "stopped" if self._state == "completed" else "empty"


def create_app(store=None):
    app = FastAPI(title="ML-DDoS-Detector dashboard")
    store = DashboardStore() if store is None else store

    def respond(section, response):
        payload, headers = store.snapshot(section)
        response.headers.update(headers)
        return payload

    @app.get("/api/health")
    def health(response: Response):
        return respond("health", response)

    @app.get("/api/metrics")
    def metrics(response: Response):
        return respond("metrics", response)

    @app.get("/api/detections")
    def detections(response: Response):
        return respond("detections", response)

    @app.get("/api/blocks")
    def blocks(response: Response):
        return respond("blocks", response)

    root = Path(__file__).resolve().parents[1]
    if (root / "frontend").is_dir():
        @app.get("/docs/api-examples.json", include_in_schema=False)
        def mock_examples():
            return FileResponse(root / "docs" / "api-examples.json")

        app.mount("/frontend", StaticFiles(directory=root / "frontend", html=True), name="frontend")
    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve a dashboard snapshot from an offline monitor replay")
    parser.add_argument("--replay", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--victim")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    import uvicorn
    from .monitor import main as run_monitor

    store = DashboardStore()
    monitor_args = ["--replay", args.replay, "--model", args.model, "--log", args.log]
    if args.victim:
        monitor_args.extend(("--victim", args.victim))
    if run_monitor(monitor_args, deliver=store.ingest):
        return 1
    uvicorn.run(create_app(store), host="127.0.0.1", port=args.port)
    return 0


app = create_app()

if __name__ == "__main__":
    raise SystemExit(main())
