"""Label, count and (optionally) score one re-recorded lab session for issue #49.

Rebuilds the labeling rules of the original lab pilot (the lost tools/lab_join.py,
as recorded in the lab-handoff.zip coverage files on issue #3):

- A packet from the attacker inside a logged scenario run (first to last sent
  packet, attacker clock offset applied, +/- slack) is attack-labelled, including
  the attacker's RSTs to the server's SYN-ACKs.
- A packet from the client inside its logged HTTP run is benign-labelled.
- Anything else is unknown.
- A window touching the first/last selected window or within slack of any attack
  run start/stop is excluded as a boundary.
- A window overlapping an attack run is attack if at least 80% of its inbound
  packets are attack-labelled, otherwise excluded as mixed.
- Any other non-empty window is benign only if all its packets are benign-labelled.

Windows are one-second Unix-epoch windows over the repository's inbound IPv4
selection (ddos_detector.frames.iter_packets). Features come from
ddos_detector.offline.extract_pcap. Per-source counts are diagnostics only.

Usage:
  python -m tools.lab_session_export --session S1 --pcap server.pcap \
      --attacker-runs results/rerec-S1/scenarios --client-run results/rerec-S1/client/<uuid> \
      --tcpdump-dropped 0 --out export-S1 [--model DIR]
"""
import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from importlib import metadata as importlib_metadata
from pathlib import Path

from ddos_detector.config import Config
from ddos_detector.contracts import FEATURE_SCHEMA_VERSION
from ddos_detector.frames import iter_packets
from ddos_detector.normalize import SkipCounter
from ddos_detector.offline import extract_pcap
from ddos_detector.training_data import file_sha256

SYN, ACK = 0x02, 0x10
ATTACKER, CLIENT = "10.10.10.30", "10.10.10.20"
ATTACK_SHARE = 0.8
TOOL_VERSION = "lab-rerec-1"
# Reported in lab-handoff.zip (issue #3) for the lost original sessions, for comparison only.
ORIGINAL_REPORTED = {
    "S1": {"attack": 253, "benign": 527, "excluded": 151, "syn": 163, "udp": 90, "mixed": 72, "boundary": 79},
    "S2": {"attack": 250, "benign": 528, "excluded": 153, "syn": 162, "udp": 88, "mixed": 74, "boundary": 79},
}


def syn_only(packet):
    return packet.proto == "tcp" and packet.flags is not None and bool(packet.flags & SYN) and not packet.flags & ACK


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_attack_runs(directory, offset):
    """Scenario runs under directory: (used, ignored). Times are shifted onto the server clock."""
    used, ignored = [], []
    for run_json in sorted(Path(directory).glob("*/run.json")):
        meta = json.loads(run_json.read_text(encoding="utf-8"))
        if meta.get("schema_version") != "scenario-draft-1":
            raise ValueError(f"{run_json}: not a scenario-draft-1 run")
        sent = [float(row["epoch_seconds"]) for row in read_csv(run_json.parent / meta["activity_file"])
                if row["outcome"] == "sent"]
        entry = {"run_id": meta["run_id"], "protocol": meta["settings"]["protocol"],
                 "rate": meta["settings"]["rate"], "duration": meta["settings"]["duration"],
                 "port": meta["settings"]["port"], "state": meta["state"],
                 "reported_sent": (meta.get("summary") or {}).get("sent"),
                 "run_json_sha256": file_sha256(run_json),
                 "activity_sha256": file_sha256(run_json.parent / meta["activity_file"])}
        if meta["state"] != "complete" or not sent:
            ignored.append({**entry, "reason": "state not complete" if meta["state"] != "complete" else "no sent packets"})
            continue
        used.append({**entry, "start": min(sent) + offset, "stop": max(sent) + offset, "sent_rows": len(sent)})
    return sorted(used, key=lambda run: run["start"]), ignored


def load_client_run(directory, offset):
    directory = Path(directory)
    meta = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    if meta.get("schema_version") != "draft-2":
        raise ValueError(f"{directory}: not a draft-2 HTTP client run")
    rows = read_csv(directory / meta["requests_file"])
    if not rows:
        raise ValueError(f"{directory}: no requests")
    starts = [float(row["epoch_seconds"]) for row in rows]
    ends = [float(row["epoch_seconds"]) + float(row["elapsed_ms"] or 0) / 1000 for row in rows]
    return {"run_id": meta["run_id"], "state": meta["state"], "rate": meta["settings"].get("rate"),
            "attempted": len(rows), "start": min(starts) + offset, "stop": max(ends) + offset,
            "run_json_sha256": file_sha256(directory / "run.json"),
            "requests_sha256": file_sha256(directory / meta["requests_file"])}


def packet_label(packet, runs, client, slack):
    if packet.src == ATTACKER and any(run["start"] - slack <= packet.ts <= run["stop"] + slack for run in runs):
        return "attack"
    if packet.src == CLIENT and client["start"] - slack <= packet.ts <= client["stop"] + slack:
        return "benign"
    return "unknown"


def label_windows(windows, runs, slack):
    """windows: {epoch second: per-window tallies}. Returns {second: (label, protocol, reason)}."""
    if not windows:
        return {}
    first, last = min(windows), max(windows)
    out = {}
    for second in range(first, last + 1):
        tally = windows.get(second)
        lo, hi = second, second + 1
        if second in (first, last):
            out[second] = ("excluded", None, "capture edge")
            continue
        if any(lo < edge + slack and hi > edge - slack for run in runs for edge in (run["start"], run["stop"])):
            out[second] = ("excluded", None, "run start/stop boundary")
            continue
        if tally is None or tally["total"] == 0:
            out[second] = ("excluded", None, "empty")
            continue
        overlapping = [run for run in runs if lo < run["stop"] and hi > run["start"]]
        if overlapping:
            share = tally["attack"] / tally["total"]
            if share >= ATTACK_SHARE:
                out[second] = ("attack", overlapping[0]["protocol"], None)
            else:
                out[second] = ("excluded", None, "inside attack run, attack share below 80% (mixed)")
        elif tally["benign"] == tally["total"]:
            out[second] = ("benign", None, None)
        else:
            out[second] = ("excluded", None, "non-client packets outside attack runs")
    return out


def export(session, pcap, attacker_runs, client_run, out, *, offset_attacker=0.0, offset_client=0.0,
           slack=2.5, tcpdump_dropped=None, model=None, config=None):
    config = config or Config()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    runs, ignored = load_attack_runs(attacker_runs, offset_attacker)
    client = load_client_run(client_run, offset_client)

    windows = defaultdict(lambda: {"total": 0, "attack": 0, "benign": 0, "unknown": 0,
                                   "sources": defaultdict(lambda: [0, 0])})
    reasons = Counter()
    captured = Counter()
    skips = SkipCounter()
    for packet in iter_packets(pcap, config.victim_ip, skips=skips):
        label = packet_label(packet, runs, client, slack)
        tally = windows[math.floor(packet.ts)]
        tally["total"] += 1
        tally[label] += 1
        counts = tally["sources"][packet.src, packet.proto]
        counts[0] += 1
        counts[1] += syn_only(packet)
        reasons[label] += 1
        if packet.src == ATTACKER:
            for index, run in enumerate(runs):
                if run["start"] - slack <= packet.ts <= run["stop"] + slack and (
                        (run["protocol"] == "syn" and syn_only(packet))
                        or (run["protocol"] == "udp" and packet.proto == "udp")):
                    captured[index] += 1

    records, feature_skips = extract_pcap(pcap, config)
    by_second = {math.floor(record.window_start): record for record in records}
    labels = label_windows(windows, runs, slack)

    scorer = None
    if model is not None:
        from ddos_detector.training import load_model, score_loaded_record
        pipeline, model_meta = load_model(model)
        scorer = lambda record: score_loaded_record(pipeline, model_meta, record)  # noqa: E731
    capture_valid = tcpdump_dropped == 0

    counts = Counter()
    mismatches = 0
    with (out / "windows.jsonl").open("x", encoding="utf-8") as handle:
        for second, (label, protocol, reason) in sorted(labels.items()):
            tally = windows.get(second, {"total": 0, "attack": 0, "benign": 0, "unknown": 0, "sources": {}})
            record = by_second.get(second)
            if (record.packet_count if record else 0) != tally["total"]:
                mismatches += 1
            score = None
            if scorer and record is not None and record.packet_count > 0 and capture_valid and not record.capped:
                score = scorer({"capture_state": "valid", "capped": record.capped, "window_seconds": 1.0,
                                "feature_schema_version": FEATURE_SCHEMA_VERSION, "features": record.features})
            counts[label] += 1
            if label == "attack":
                counts[protocol] += 1
            if reason:
                counts[reason] += 1
            row = {"window_id": f"lab-rerec-{session}-{second}", "session": session, "window_start": second,
                   "label": label, "attack_protocol": protocol, "exclusion_reason": reason,
                   "packet_count": tally["total"], "attack_packets": tally["attack"],
                   "benign_packets": tally["benign"], "unknown_packets": tally["unknown"],
                   "attack_share": round(tally["attack"] / tally["total"], 6) if tally["total"] else None,
                   "features": record.features if record else None, "capped": record.capped if record else False,
                   "source_counts": [{"src": src, "proto": proto, "packets": n, "syn_only": syn}
                                     for (src, proto), (n, syn) in sorted(tally["sources"].items())],
                   "score": score}
            handle.write(json.dumps(row, allow_nan=False) + "\n")

    run_checks = [{**{k: run[k] for k in ("run_id", "protocol", "rate", "duration", "port", "state",
                                           "reported_sent", "sent_rows", "run_json_sha256", "activity_sha256")},
                   "start_server_epoch": run["start"], "stop_server_epoch": run["stop"],
                   "captured_matching_packets": captured[index],
                   "sent_equals_captured": captured[index] == run["reported_sent"]}
                  for index, run in enumerate(runs)]
    from ddos_detector.training import source_revision, versions
    manifest = {
        "tool": "tools/lab_session_export.py", "tool_version": TOOL_VERSION, "session": session,
        "data_kind": "rerecorded_lab_session_unreviewed", "source_revision": source_revision(),
        "versions": {**versions(), "ddos_detector": _package_version()},
        "capture": {"file": Path(pcap).name, "sha256": file_sha256(pcap), "tcpdump_dropped": tcpdump_dropped,
                    "valid_for_scoring": capture_valid},
        "settings": {"victim_ip": config.victim_ip, "attacker": ATTACKER, "client": CLIENT,
                     "offset_attacker_seconds": offset_attacker, "offset_client_seconds": offset_client,
                     "slack_seconds": slack, "attack_share_threshold": ATTACK_SHARE,
                     "window_seconds": 1.0, "window_alignment": "unix_epoch",
                     "scope": "protected_server_inbound_ipv4_tcp_udp_icmp",
                     "size_definition": "ipv4_total_length_bytes",
                     "feature_schema_version": FEATURE_SCHEMA_VERSION},
        "attack_runs": run_checks, "ignored_attack_runs": ignored, "client_run": client,
        "packet_labels": dict(reasons), "selection_skips": dict(skips), "feature_skips": dict(feature_skips),
        "window_counts": dict(counts), "windows_total": len(labels), "window_packet_count_mismatches": mismatches,
        "original_reported_counts": ORIGINAL_REPORTED.get(session),
        "model": None if model is None else {"directory": str(model), "model_sha256": model_meta["model_sha256"],
                                             "decision_threshold": model_meta["decision_threshold"]},
        "windows_file": "windows.jsonl", "windows_sha256": file_sha256(out / "windows.jsonl"),
        "limits": ["Labels assume the lab network held only the server, client and attacker.",
                   "Captured-vs-sent matches source and protocol (SYN-only for TCP), not destination port.",
                   "Source counts are diagnostics, never model inputs."],
    }
    with (out / "manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return manifest


def _package_version():
    try:
        return importlib_metadata.version("ddos-detector")
    except importlib_metadata.PackageNotFoundError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--session", required=True, help="session name, e.g. S1")
    ap.add_argument("--pcap", required=True, help="server capture")
    ap.add_argument("--attacker-runs", required=True, help="scenarios --output folder holding the run UUID folders")
    ap.add_argument("--client-run", required=True, help="the HTTP client's run UUID folder")
    ap.add_argument("--out", required=True, help="new export folder (must not exist)")
    ap.add_argument("--offset-attacker", type=float, default=0.0, help="seconds added to attacker times")
    ap.add_argument("--offset-client", type=float, default=0.0, help="seconds added to client times")
    ap.add_argument("--slack", type=float, default=2.5)
    ap.add_argument("--tcpdump-dropped", type=int, help="'packets dropped by kernel' from tcpdump; 0 enables scoring")
    ap.add_argument("--model", help="trusted model folder (metadata.json + model.joblib)")
    args = ap.parse_args(argv)
    manifest = export(args.session, args.pcap, args.attacker_runs, args.client_run, args.out,
                      offset_attacker=args.offset_attacker, offset_client=args.offset_client, slack=args.slack,
                      tcpdump_dropped=args.tcpdump_dropped, model=args.model)
    print(json.dumps({"out": args.out, "window_counts": manifest["window_counts"],
                      "original_reported_counts": manifest["original_reported_counts"],
                      "sent_equals_captured": [run["sent_equals_captured"] for run in manifest["attack_runs"]],
                      "window_packet_count_mismatches": manifest["window_packet_count_mismatches"]}, indent=2))


if __name__ == "__main__":
    main()
