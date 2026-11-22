"""Reconcile the fixed issue #48 handoff; does not run supplied scripts or live traffic."""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path
import zipfile

from scapy.all import Ether, IP, TCP
from scapy.utils import RawPcapReader

from ddos_detector.features import Packet, extract_features
from ddos_detector.training import load_model, score_loaded_record, write_json


ARCHIVE_SHA = "3979d320fe760c0ad2e0b549c22d719fb3c330b18804651c0af2cdf9b0b572e6"
MODEL_SHA = "44f2ae879b63414c8af7d7c1165e7a0d462c9545f6190f7a8a7b2f00aa9e9fe7"


def epoch(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def review(archive, model_directory):
    archive = Path(archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA
    model, metadata = load_model(model_directory)
    assert metadata["model_sha256"] == MODEL_SHA
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        assert len(names) == len(set(names))
        manifest = {}
        for line in z.read("SHA256SUMS.txt").decode().splitlines():
            digest, name = line.split("  ", 1)
            assert name not in manifest
            manifest[name] = digest
            assert hashlib.sha256(z.read(name)).hexdigest() == digest, name
        assert set(names) == set(manifest) | {"SHA256SUMS.txt"}
        def read_json(name):
            return json.loads(z.read(name))
        def audit(run):
            return [json.loads(line) for line in z.read(
                f"server/live-trained-model-{run}.jsonl").decode().splitlines()]
        totals = {}
        windows_by_run = {}
        for run, expected in (("01", 70), ("02", 57), ("03", 46)):
            rows = audit(run)
            windows = [r for r in rows if r["record_type"] == "window"]
            assert len(windows) == expected
            assert rows[0]["status"] == "started" and rows[-1]["status"] == "completed"
            assert rows[-1]["windows"] == rows[-1]["scored"] == expected
            assert rows[-1]["late_dropped"] == rows[-1]["partial_windows_discarded"] == 0
            assert rows[-1]["gaps"] == []
            assert all(r["monitor_only"] is True and r["model_sha256"] == MODEL_SHA
                       and r["data_kind"] == "reviewed_packet_windows" for r in rows)
            assert all(w["scored"] and not w["predicted_attack"] for w in windows)
            by_start = {int(w["window_start"]): w for w in windows}
            assert len(by_start) == expected
            windows_by_run[run] = by_start
            files = [n for n in names if n.startswith(f"client/w48-client-{run}/")
                     and n.endswith("/requests.csv")]
            assert len(files) == 1
            requests = list(csv.DictReader(io.StringIO(z.read(files[0]).decode())))
            assert all(r["status_code"] == "200" and r["outcome"] == "http_response"
                       for r in requests)
            client = read_json(files[0].replace("requests.csv", "run.json"))
            assert client["summary"]["attempted"] == len(requests)
            totals[run] = {"windows": expected, "packets": sum(w["packet_count"] for w in windows),
                          "predicted_attacks": 0, "http_200": len(requests),
                          "achieved_http_requests_per_second": client["summary"]["achieved_requests_per_second"],
                          "skipped_client_lag": client["summary"]["skipped_due_to_lag"],
                          "max_processing_delay_s": rows[-1]["max_processing_delay_s"],
                          "monitor_kernel_drops": rows[-1]["kernel_drops"]}
        metric_checks, detection_checks, snapshot_count = Counter(), Counter(), Counter()
        unique_points = defaultdict(dict)
        newest = defaultdict(list)
        for run in ("02", "03"):
            for number in range(1, 5 if run == "02" else 4):
                prefix = f"server/snapshots-{run}/s{number}"
                snapshots = {}
                for endpoint in ("health", "metrics", "detections", "blocks"):
                    headers = z.read(f"{prefix}-{endpoint}.headers").decode().lower()
                    for value in ("http/1.1 200 ok", "cache-control: no-store",
                                  "x-dashboard-source: live", "x-dashboard-freshness: current",
                                  "x-dashboard-data-kind: reviewed_packet_windows"):
                        assert value in headers
                    snapshots[endpoint] = read_json(f"{prefix}-{endpoint}.json")
                health = snapshots["health"]
                assert (health["capture_status"], health["model_status"], health["firewall_status"],
                        health["mitigation_mode"]) == ("running", "loaded", "unavailable", "monitor_only")
                assert snapshots["blocks"]["blocks"] == []
                for point in snapshots["metrics"]["points"]:
                    start = int(epoch(point["window_start"]))
                    window = windows_by_run[run][start]
                    assert point["window_seconds"] == 1
                    assert point["packets_per_second"] == window["packet_count"]
                    unique_points[run][start] = point
                    metric_checks[run] += 1
                newest[run].append(max(epoch(p["window_start"]) for p in snapshots["metrics"]["points"]))
                for detection in snapshots["detections"]["detections"]:
                    start = int(detection["id"].removeprefix("aggregate-"))
                    window = windows_by_run[run][start]
                    assert detection["scope"] == "aggregate" and detection["source_ip"] is None
                    assert detection["model_version"] == MODEL_SHA
                    assert detection["attack_score"] == window["attack_score"]
                    assert detection["decision"] == "no_action"
                    assert abs(epoch(detection["detected_at"]) - (window["logged_at"] + window["scoring_s"])) < 0.000002
                    detection_checks[run] += 1
                snapshot_count[run] += 1
            assert newest[run] == sorted(set(newest[run]))
        packets, raw_count = defaultdict(list), 0
        reader = RawPcapReader(io.BytesIO(z.read("server/tcpdump-03.pcap")))
        assert reader.linktype == 1
        for raw, timestamp in reader:
            raw_count += 1
            frame = Ether(raw)
            if IP not in frame:
                continue
            ip = frame[IP]
            if ip.dst != "10.10.10.10" or ip.proto not in (1, 6, 17):
                continue
            ts = timestamp.sec + timestamp.usec / 1_000_000
            protocol = {1: "icmp", 6: "tcp", 17: "udp"}[ip.proto]
            flags = int(ip[TCP].flags) if protocol == "tcp" and TCP in ip else None if protocol == "tcp" else 0
            packets[math.floor(ts)].append(Packet(ts, ip.src, protocol, int(ip.len), flags))
        reader.close()
        assert raw_count == 308
        assert sum(map(len, packets.values())) == 204
        scored_again = 0
        for start, window in windows_by_run["03"].items():
            assert len(packets[start]) == window["packet_count"]
            features = extract_features(packets[start], 1)
            scored = score_loaded_record(model, metadata, {
                "capture_state": "valid", "capped": False, "feature_schema_version": "1",
                "window_seconds": 1, "features": features})
            assert scored["attack_score"] == window["attack_score"]
            assert scored["predicted_attack"] == window["predicted_attack"]
            scored_again += 1
        for start, point in unique_points["03"].items():
            assert point["bytes_per_second"] == sum(p.size for p in packets[start])
        failed = [json.loads(line) for line in z.read("server/startup-fail-nonroot-01.jsonl").decode().splitlines()]
        assert [r["status"] for r in failed] == ["started", "unavailable"]
        assert failed[-1]["windows"] == 0 and "CAP_NET_RAW" in failed[-1]["reason"]
        live_text = z.read("dashboard/live-2.txt").decode()
        stopped_text = z.read("dashboard/live-3-stopped-10s.txt").decode()
        assert "current, live, reviewed_packet_windows" in live_text
        assert "all displayed data is stale" in stopped_text and "Capture\nError" in stopped_text
        return {
            "archive_sha256": ARCHIVE_SHA, "archive_bytes": archive.stat().st_size,
            "manifest_members_verified": len(manifest), "tested_revision": "f99ca6bce1f63441fca3c1636558293c41f07aa3",
            "model_sha256": MODEL_SHA, "runs": totals,
            "snapshots_per_run": dict(snapshot_count), "metric_point_checks": dict(metric_checks),
            "detection_checks": dict(detection_checks),
            "unique_metric_windows": {run: len(points) for run, points in unique_points.items()},
            "advancing_latest_window_epoch": dict(newest),
            "run03_independent_pcap": {"frames": raw_count, "selected_inbound_packets": 204,
                "packet_count_windows_matched": 46, "model_scores_reproduced": scored_again,
                "ip_byte_rate_windows_matched": len(unique_points["03"]),
                "tcpdump_reported_kernel_drops": 0},
            "failure_audit_verified": True, "dashboard_text_verified": True,
            "final_test_scored": False, "enforcement_tested": False,
            "limits": ["Benign traffic integration, not attack accuracy or active protection.",
                       "No access to the running VM; checkout, runtime, exits and clock correction remain operator reports.",
                       "Monitor kernel loss is null; tcpdump zero drops describes its separate capture.",
                       "Run 01 has no API snapshots; use runs 02/03 for API acceptance.",
                       "Requested HTTP rate 5/s was not achieved; use actual request records.",
                       "S3 held-out model outcomes were not inspected."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if Path(args.output).exists():
        raise ValueError("Use a new review output")
    report = review(args.archive, args.model)
    write_json(args.output, report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
