"""Read-only dashboard API and bounded monitor state."""
import argparse
from collections import deque
from datetime import datetime, timezone
import json
import math
import sys
from threading import Lock, Thread
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
        self._archived = False
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

    @classmethod
    def from_audit_log(cls, lines):
        """Read a terminated monitor run into a bounded, historical store."""
        store = cls()
        store._archived = True
        window_count = 0
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict) or event.get("monitor_only") is not True:
                    raise ValueError("Expected a monitor-only record")
                if event.get("record_type") == "window":
                    utc_timestamp(event["logged_at"])
                    store._ingest_window(event, None)
                    window_count += 1
                else:
                    store.ingest(event)
                    if event.get("status") in ("completed", "unavailable") and event.get("windows") != window_count:
                        raise ValueError("Terminal window count does not match audit records")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"Invalid monitor audit record at line {line_number}: {exc}") from exc
        if store._state not in ("completed", "unavailable"):
            raise ValueError("Monitor audit log has no terminal status")
        return store

    def _ingest_status(self, event):
        state = event["status"]
        source = event["source_mode"]
        data_kind = event["data_kind"]
        model = event["model_sha256"]
        if source not in ("replay", "live") or data_kind not in ("synthetic", "reviewed_packet_windows"):
            raise ValueError("Invalid monitor provenance")
        if not isinstance(model, str) or not model:
            raise ValueError("Missing model identity")
        if self._state == "idle" and state in ("started", "unavailable"):
            self._source, self._data_kind, self._model = source, data_kind, model
            self._started_at = event["logged_at"]
        elif (self._state != "started" or state not in ("completed", "unavailable")
              or (source, data_kind, model) != (self._source, self._data_kind, self._model)):
            raise ValueError("Unexpected monitor lifecycle transition")
        self._state = state

    def _ingest_window(self, event, record):
        start, end = event["window_start"], event["window_end"]
        timestamp = utc_timestamp(start)
        utc_timestamp(end)
        if (self._state != "started" or end - start != 1 or start % 1
                or self._last_window_end is not None and start < self._last_window_end):
            raise ValueError("Expected an ordered finalized one-second monitor window")
        packet_count = event["packet_count"]
        if type(packet_count) is not int or packet_count < 0:
            raise ValueError("Invalid packet count")
        rates = {"packets_per_second": packet_count, "bytes_per_second": None}
        if record is not None:
            if (start, end, packet_count) != (record.window_start, record.window_end, record.packet_count):
                raise ValueError("Monitor event and window disagree")
            features = record.features
            byte_rate = features["byte_rate"]
            if type(byte_rate) not in (int, float) or not math.isfinite(byte_rate) or byte_rate < 0:
                raise ValueError("Invalid byte rate")
            packet_rate = features["packet_rate"]
            if type(packet_rate) not in (int, float) or packet_count != packet_rate:
                raise ValueError("Window rate and packet count disagree")
            rates.update(packets_per_second=packet_rate, bytes_per_second=byte_rate)
        scored = event["scored"]
        if type(scored) is not bool:
            raise ValueError("Invalid scoring status")
        detection = None
        if scored:
            score = event["attack_score"]
            threshold = event["decision_threshold"]
            if (not packet_count or (record is not None and record.capped)
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
            source = f"recorded_{self._source}" if self._archived else self._source
            headers = {"Cache-Control": "no-store", "X-Dashboard-Freshness": freshness,
                       "X-Dashboard-Source": source, "X-Dashboard-Data-Kind": self._data_kind}
            return {"schema_version": "1", "updated_at": utc_timestamp(now), **data}, headers

    def _freshness(self, now):
        if self._state == "unavailable":
            return "unavailable"
        if self._archived or self._source == "replay":
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


def serve_live(store, monitor_args, port):
    """Serve the shared store while capture and scoring run in the foreground."""
    import uvicorn
    from .monitor import main as run_monitor

    server = uvicorn.Server(uvicorn.Config(create_app(store), host="127.0.0.1", port=port))
    errors = []

    def serve():
        try:
            server.run()
        except (Exception, SystemExit) as exc:
            errors.append(exc)

    worker = Thread(target=serve, name="dashboard-http", daemon=True)
    worker.start()
    result = 2
    try:
        deadline = time.monotonic() + 10
        while not server.started and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not server.started or not worker.is_alive():
            print("Dashboard server failed to start", file=sys.stderr)
        else:
            result = run_monitor(monitor_args, deliver=store.ingest)
    except KeyboardInterrupt:
        result = 130
    finally:
        server.should_exit = True
        worker.join(timeout=5)
    if errors or worker.is_alive():
        print("Dashboard server did not finish cleanly", file=sys.stderr)
        return 2
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve live monitor data, a replay or a recorded audit log")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--replay", metavar="PCAP")
    source.add_argument("--interface", help="Linux lab capture interface")
    source.add_argument("--audit-log", type=Path, metavar="JSONL")
    parser.add_argument("--model")
    parser.add_argument("--log")
    parser.add_argument("--victim")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--duration", type=float, help="Optional live capture duration in seconds")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    if args.duration is not None and (args.interface is None or not math.isfinite(args.duration) or args.duration <= 0):
        parser.error("--duration requires --interface and finite positive seconds")

    import uvicorn
    if args.audit_log is not None:
        if any(option is not None for option in (args.model, args.log, args.victim)):
            parser.error("--model, --log and --victim apply only to --replay")
        try:
            with args.audit_log.open(encoding="utf-8") as handle:
                store = DashboardStore.from_audit_log(handle)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    elif args.interface is not None:
        if not args.model or not args.log:
            parser.error("--interface requires --model and --log")
        monitor_args = ["--interface", args.interface, "--model", args.model, "--log", args.log]
        if args.victim:
            monitor_args.extend(("--victim", args.victim))
        if args.duration is not None:
            monitor_args.extend(("--duration", str(args.duration)))
        return serve_live(DashboardStore(), monitor_args, args.port)
    else:
        if not args.model or not args.log:
            parser.error("--replay requires --model and --log")
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
