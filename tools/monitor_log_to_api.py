"""Convert a monitor JSONL log into the dashboard's four-part API snapshot (docs/api-contract.md).

Stand-in for the missing backend store: it only reshapes what the monitor logged. Bytes per second
are not in the log, so they are null (the dashboard already shows null as unavailable). Detections
are aggregate-scope alerts only; no source is attributed and no block is ever created.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

MAX_DETECTIONS = 50


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def convert(lines):
    records = [json.loads(line) for line in lines if line.strip()]
    windows = [r for r in records if r.get("record_type") == "window"]
    statuses = [r for r in records if r.get("record_type") == "monitor_status"]
    if not statuses:
        raise ValueError("log has no monitor_status record")
    last = statuses[-1]
    updated = iso(max([r["logged_at"] for r in records]))
    capture = {"started": "running", "completed": "stopped"}.get(last["status"], "error")
    version = "%s-%s" % (last.get("data_kind", "unknown"), last["model_sha256"][:8])
    points = [{"window_start": iso(w["window_start"]), "window_seconds": round(w["window_end"] - w["window_start"], 3),
               "packets_per_second": w["packet_count"] / (w["window_end"] - w["window_start"]),
               "bytes_per_second": None} for w in windows]
    detections = [{"id": "det-%04d" % i, "detected_at": iso(w["logged_at"]), "scope": "aggregate",
                   "source_ip": None, "attack_score": w["attack_score"], "model_version": version,
                   "decision": "alert", "aggregate_detection_id": None, "attribution": None}
                  for i, w in enumerate((w for w in windows if w.get("predicted_attack")), 1)]
    return {"health": {"schema_version": "1", "updated_at": updated, "capture_status": capture,
                       "model_status": "loaded", "firewall_status": "unavailable", "mitigation_mode": "monitor_only"},
            "metrics": {"schema_version": "1", "updated_at": updated, "points": points[-MAX_DETECTIONS * 3:]},
            "detections": {"schema_version": "1", "updated_at": updated, "detections": detections[-MAX_DETECTIONS:]},
            "blocks": {"schema_version": "1", "updated_at": updated, "blocks": []}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log")
    parser.add_argument("out")
    args = parser.parse_args(argv)
    with open(args.log, encoding="utf-8") as handle:
        snapshot = convert(handle)
    with open(args.out, "x", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=1)
    print("wrote", args.out, "windows:", len(snapshot["metrics"]["points"]),
          "alerts:", len(snapshot["detections"]["detections"]))


if __name__ == "__main__":
    sys.exit(main())
