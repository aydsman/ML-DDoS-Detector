"""Label, count and (optionally) score one new policy lab session for issue #49.

Per the #49 owner decision, the sessions recorded on the rebuilt lab are new,
independently identified policy-calibration and policy-validation sessions. They
do not replace the original S1/S2. The original model and score threshold are
used unchanged. The labeling rules rebuild those of the original lab pilot (the
lost tools/lab_join.py, as recorded in the lab-handoff.zip coverage files on
issue #3), with the dataset decision order of docs/dataset-plan.md:

- A packet from the attacker inside a logged scenario run (first to last sent
  packet, moved onto the server clock, +/- slack) is attack-labelled, including
  the attacker's RSTs to the server's SYN-ACKs.
- A packet from the client inside its logged HTTP run is benign-labelled.
- Anything else is unknown.
- In order, a window is excluded when it touches the first/last selected window,
  lies within slack plus clock uncertainty of an attack run start/stop, is empty,
  or holds any unknown-labelled packet. Only then: a window overlapping an attack
  run is attack at >= 80% attack share, else excluded as mixed; any other window
  is benign when all its packets are benign-labelled.

Every window from the first to the last captured second is written, including
exclusions. Each row also says whether it is eligible as policy evidence, with
the reasons when it is not. Ineligible windows must reset policy streaks.

The session is valid for scoring only when every check passes: the schedule and
complete run inventory, the client run's completion, log reconciliation, clock
evidence from before and after the session, capture coverage, zero kernel drops
and per-window reconciliation. Otherwise the export is still written as
diagnostics, with valid_for_scoring false and the reasons listed.

Usage:
  python -m tools.lab_session_export --session-id policy-calibration-2026-11-27-a \
      --pcap server.pcap --attacker-dir <attacker results/<session-id>> \
      --client-run <client results/<session-id>/client/<uuid>> \
      --clock-before clock-before.json --clock-after clock-after.json \
      --tcpdump-dropped 0 --out export [--model DIR]
"""
import argparse
import csv
import json
import math
import re
import uuid
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
TOOL_VERSION = "lab-policy-2"
SESSION_ID = re.compile(r"^policy-(calibration|validation)-\d{4}-\d{2}-\d{2}-[a-z0-9]+$")


def syn_only(packet):
    """True/False for TCP with known flags; None when the flags are unknown or not TCP."""
    if packet.proto != "tcp" or packet.flags is None:
        return None
    return bool(packet.flags & SYN) and not packet.flags & ACK


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def read_json(path, problems, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        problems.append(f"{what} missing: {path}")
    except (OSError, ValueError) as exc:
        problems.append(f"{what} unreadable: {path}: {exc}")
    return None


def session_role(session_id):
    match = SESSION_ID.match(session_id)
    if not match:
        raise ValueError("session id must look like policy-calibration-YYYY-MM-DD-a or policy-validation-YYYY-MM-DD-b")
    return match.group(1)


def load_schedule(attacker_dir, session_id, problems):
    schedule = read_json(Path(attacker_dir) / "schedule.json", problems, "attack schedule")
    if schedule is None:
        return None
    if schedule.get("session_id") != session_id:
        problems.append(f"attack schedule is for session {schedule.get('session_id')!r}, not {session_id!r}")
    if not schedule.get("runs"):
        problems.append("attack schedule lists no runs")
    return schedule


def _reconcile(rows, meta, index_field, count_field, what, problems):
    """Check log rows against their run.json: run IDs, unique indices and the summary count."""
    if any(row.get("run_id") != meta["run_id"] for row in rows):
        problems.append(f"{what}: log rows carry a different run_id")
    indices = [row.get(index_field) for row in rows]
    if len(indices) != len(set(indices)):
        problems.append(f"{what}: duplicate {index_field} in log rows")
    summary = meta.get("summary") or {}
    if summary.get(count_field) != len(rows):
        problems.append(f"{what}: summary {count_field}={summary.get(count_field)} but log has {len(rows)} rows")


def load_attack_runs(directory, offset, problems):
    """Complete scenario runs (times on the server clock) and retained incomplete/failed ones."""
    used, retained = [], []
    directory = Path(directory)
    if not directory.is_dir():
        problems.append(f"attacker scenario folder missing: {directory}")
        return used, retained
    for run_json in sorted(directory.glob("*/run.json")):
        meta = read_json(run_json, problems, "scenario run")
        if meta is None:
            continue
        if meta.get("schema_version") != "scenario-draft-1":
            problems.append(f"{run_json}: not a scenario-draft-1 run")
            continue
        what = f"attack run {meta['run_id']}"
        activity = run_json.parent / meta["activity_file"]
        rows = read_csv(activity) if activity.exists() else []
        settings = meta.get("settings") or {}
        sent = [float(row["epoch_seconds"]) for row in rows if row["outcome"] == "sent"]
        entry = {"run_id": meta["run_id"], "protocol": settings.get("protocol"), "rate": settings.get("rate"),
                 "duration": settings.get("duration"), "port": settings.get("port"), "state": meta.get("state"),
                 "reported_sent": (meta.get("summary") or {}).get("sent"), "sent_rows": len(sent),
                 "run_json_sha256": file_sha256(run_json),
                 "activity_sha256": file_sha256(activity) if activity.exists() else None}
        reason = None
        if not activity.exists():
            reason = "activity log missing"
        elif meta.get("state") != "complete":
            reason = f"state {meta.get('state')!r}"
        elif not sent:
            reason = "no sent packets"
        if reason:
            retained.append({**entry, "reason": reason})
            problems.append(f"{what}: {reason}")
            continue
        _reconcile(rows, meta, "packet_index", "attempted", what, problems)
        if entry["reported_sent"] != len(sent):
            problems.append(f"{what}: summary sent={entry['reported_sent']} but log has {len(sent)} sent rows")
        used.append({**entry, "start": min(sent) + offset, "stop": max(sent) + offset})
    return sorted(used, key=lambda run: run["start"]), retained


def check_inventory(runs, schedule, problems):
    """Each scheduled run must have exactly one complete run with the same settings, in order."""
    if schedule is None:
        return
    planned = schedule.get("runs") or []
    if len(runs) != len(planned):
        problems.append(f"run inventory: {len(runs)} complete runs, schedule has {len(planned)}")
    for number, (run, plan) in enumerate(zip(runs, planned), start=1):
        for key in ("protocol", "port", "rate", "duration"):
            if run[key] != plan.get(key) and not (
                    isinstance(run[key], (int, float)) and isinstance(plan.get(key), (int, float))
                    and float(run[key]) == float(plan[key])):
                problems.append(f"run {number}: {key} {run[key]!r} differs from schedule {plan.get(key)!r}")


def load_client_run(directory, offset, plan, problems):
    directory = Path(directory)
    meta = read_json(directory / "run.json", problems, "client run")
    if meta is None:
        return None
    if meta.get("schema_version") != "draft-2":
        problems.append(f"{directory}: not a draft-2 HTTP client run")
        return None
    requests = directory / meta["requests_file"]
    rows = read_csv(requests) if requests.exists() else []
    settings = meta.get("settings") or {}
    if meta.get("state") != "complete":
        problems.append(f"client run {meta['run_id']}: state {meta.get('state')!r}, not complete")
    if not rows:
        problems.append(f"client run {meta['run_id']}: no request rows")
        return None
    _reconcile(rows, meta, "request_index", "attempted", f"client run {meta['run_id']}", problems)
    rate, duration = settings.get("request_rate"), settings.get("duration_seconds")
    if plan:
        for key, value in (("rate", rate), ("duration", duration)):
            if value is None or float(value) != float(plan.get(key, math.nan)):
                problems.append(f"client run: {key} {value!r} differs from schedule {plan.get(key)!r}")
    starts = [float(row["epoch_seconds"]) for row in rows]
    ends = [float(row["epoch_seconds"]) + float(row["elapsed_ms"] or 0) / 1000 for row in rows]
    return {"run_id": meta["run_id"], "state": meta.get("state"), "rate": rate, "duration": duration,
            "attempted": len(rows), "summary": meta.get("summary"),
            "start": min(starts) + offset, "stop": max(ends) + offset,
            "run_json_sha256": file_sha256(directory / "run.json"), "requests_sha256": file_sha256(requests)}


def load_clocks(before_path, after_path, slack, problems):
    """Validate timestamped endpoint calibrations, then estimate relative offsets.

    Bounds apply to the observed samples. Applying them inside the session also
    assumes continuous clocks without unobserved steps; retain that limitation.
    """
    shifts = {"attacker": 0.0, "client": 0.0}
    uncertainty = {"attacker": None, "client": None}
    detail = {"files": {}, "samples": {},
              "assumption": "Endpoint calibration assumes no unobserved clock step or excursion during the session."}
    for when, path in (("before", before_path), ("after", after_path)):
        if path is None:
            problems.append(f"clock evidence missing: no {when}-session clock file")
            continue
        data = read_json(path, problems, f"{when}-session clock file")
        if data is None:
            continue
        detail["files"][when] = file_sha256(path)
        values = {}
        for vm in ("server", "client", "attacker"):
            sample = (data.get("vms") or {}).get(vm) if isinstance(data, dict) else None
            valid = isinstance(sample, dict)
            for key in ("offset_seconds", "bound_seconds", "host_epoch"):
                value = sample.get(key) if isinstance(sample, dict) else None
                valid = valid and isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
            if valid:
                count = sample.get("samples")
                valid = (sample["bound_seconds"] >= 0 and sample["host_epoch"] > 0
                         and isinstance(count, int) and not isinstance(count, bool) and count > 0)
            if not valid:
                problems.append(f"{when}-session clock evidence invalid for {vm}: need finite offsets, "
                                "nonnegative bounds, sample epoch and positive sample count")
            else:
                values[vm] = {key: sample[key] for key in ("offset_seconds", "bound_seconds", "host_epoch", "samples")}
        if len(values) == 3:
            detail["samples"][when] = values
    if len(detail["samples"]) != 2:
        return shifts, uncertainty, detail
    for vm in ("server", "client", "attacker"):
        if detail["samples"]["before"][vm]["host_epoch"] >= detail["samples"]["after"][vm]["host_epoch"]:
            problems.append(f"clock evidence for {vm} is not ordered before then after")
    for vm in ("attacker", "client"):
        pairs = [(detail["samples"][w]["server"]["offset_seconds"] - detail["samples"][w][vm]["offset_seconds"],
                  detail["samples"][w]["server"]["bound_seconds"] + detail["samples"][w][vm]["bound_seconds"])
                 for w in ("before", "after")]
        (shift_b, bound_b), (shift_a, bound_a) = pairs
        shifts[vm] = (shift_b + shift_a) / 2
        uncertainty[vm] = abs(shift_a - shift_b) / 2 + max(bound_b, bound_a)
        detail[vm] = {"shift_before": shift_b, "shift_after": shift_a, "bound_before": bound_b,
                      "bound_after": bound_a, "shift_used": shifts[vm], "uncertainty": uncertainty[vm]}
        if uncertainty[vm] > slack:
            problems.append(f"{vm} clock uncertainty {uncertainty[vm]:.3f} s exceeds the {slack} s slack")
    return shifts, uncertainty, detail


def check_clock_coverage(detail, first_ts, last_ts, problems):
    """Reject stale, copied or mid-recording clock samples, under the stated continuity assumption."""
    samples = detail.get("samples", {})
    if first_ts is None or len(samples) != 2:
        return
    before, after = samples["before"], samples["after"]
    latest_before = max(s["host_epoch"] + s["bound_seconds"] for s in before.values())
    latest_before += before["server"]["offset_seconds"] + before["server"]["bound_seconds"]
    earliest_after = min(s["host_epoch"] - s["bound_seconds"] for s in after.values())
    earliest_after += after["server"]["offset_seconds"] - after["server"]["bound_seconds"]
    if latest_before > first_ts:
        problems.append("before-session clock measurements do not precede the capture")
    if earliest_after < last_ts:
        problems.append("after-session clock measurements do not follow the capture")


def packet_label(packet, runs, client, slack):
    if packet.src == ATTACKER and any(run["start"] - slack <= packet.ts <= run["stop"] + slack for run in runs):
        return "attack"
    if client and packet.src == CLIENT and client["start"] - slack <= packet.ts <= client["stop"] + slack:
        return "benign"
    return "unknown"


def label_windows(windows, runs, slack, boundary=None):
    """windows: {epoch second: tallies}. Returns {second: (label, protocol, reason)} for every second."""
    if not windows:
        return {}
    boundary = slack if boundary is None else boundary
    first, last = min(windows), max(windows)
    out = {}
    for second in range(first, last + 1):
        tally = windows.get(second)
        lo, hi = second, second + 1
        if second in (first, last):
            out[second] = ("excluded", None, "capture edge")
        elif any(lo < edge + boundary and hi > edge - boundary for run in runs for edge in (run["start"], run["stop"])):
            out[second] = ("excluded", None, "run start/stop boundary")
        elif tally is None or tally["total"] == 0:
            out[second] = ("excluded", None, "empty")
        elif tally["unknown"]:
            out[second] = ("excluded", None, "unknown packet labels")
        elif overlapping := [run for run in runs if lo < run["stop"] and hi > run["start"]]:
            if tally["attack"] / tally["total"] >= ATTACK_SHARE:
                out[second] = ("attack", overlapping[0]["protocol"], None)
            else:
                out[second] = ("excluded", None, "inside attack run, attack share below 80% (mixed)")
        elif tally["benign"] == tally["total"]:
            out[second] = ("benign", None, None)
        else:
            out[second] = ("excluded", None, "non-client packets outside attack runs")
    return out


def _empty_tally():
    return {"total": 0, "attack": 0, "benign": 0, "unknown": 0, "tcp_flags_unknown": 0,
            "sources": defaultdict(lambda: {"packets": 0, "flags_known": 0, "flags_unknown": 0, "syn_only": 0})}


def export(session_id, pcap, attacker_dir, client_run, out, *, clock_before=None, clock_after=None,
           slack=2.5, tcpdump_dropped=None, model=None, config=None):
    role = session_role(session_id)
    if isinstance(slack, bool) or not math.isfinite(slack) or slack < 0:
        raise ValueError("slack must be finite and nonnegative")
    config = config or Config()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    problems = []
    if tcpdump_dropped is None:
        problems.append("tcpdump kernel drop count not recorded")
    elif tcpdump_dropped != 0:
        problems.append(f"tcpdump reported {tcpdump_dropped} packets dropped by kernel")
    shifts, uncertainty, clock_detail = load_clocks(clock_before, clock_after, slack, problems)
    schedule = load_schedule(attacker_dir, session_id, problems)
    runs, retained = load_attack_runs(Path(attacker_dir) / "scenarios", shifts["attacker"], problems)
    check_inventory(runs, schedule, problems)
    client = load_client_run(client_run, shifts["client"], (schedule or {}).get("client"), problems)
    boundary = slack + (uncertainty["attacker"] or 0.0)

    windows = defaultdict(_empty_tally)
    reasons = Counter()
    captured = Counter()
    captured_unknown_flags = Counter()
    skips = SkipCounter()
    first_ts = last_ts = None
    for packet in iter_packets(pcap, config.victim_ip, skips=skips):
        first_ts = packet.ts if first_ts is None else min(first_ts, packet.ts)
        last_ts = packet.ts if last_ts is None else max(last_ts, packet.ts)
        label = packet_label(packet, runs, client, slack)
        tally = windows[math.floor(packet.ts)]
        tally["total"] += 1
        tally[label] += 1
        flag = syn_only(packet)
        source = tally["sources"][packet.src, packet.proto]
        source["packets"] += 1
        if packet.proto == "tcp":
            if flag is None:
                source["flags_unknown"] += 1
                tally["tcp_flags_unknown"] += 1
            else:
                source["flags_known"] += 1
                source["syn_only"] += flag
        reasons[label] += 1
        if packet.src == ATTACKER:
            for index, run in enumerate(runs):
                if not run["start"] - slack <= packet.ts <= run["stop"] + slack:
                    continue
                if run["protocol"] == "syn" and packet.proto == "tcp" and flag is None:
                    captured_unknown_flags[index] += 1
                elif (run["protocol"] == "syn" and flag) or (run["protocol"] == "udp" and packet.proto == "udp"):
                    captured[index] += 1

    check_clock_coverage(clock_detail, first_ts, last_ts, problems)
    if first_ts is None:
        problems.append("capture holds no selected packets")
    else:
        spans = [("client run", client)] if client else []
        spans += [(f"attack run {run['run_id']}", run) for run in runs]
        for name, span in spans:  # same +/- slack as packet labels: a run's last replies may follow it
            if span["start"] < first_ts - slack or span["stop"] > last_ts + slack:
                problems.append(f"capture does not cover the {name}")

    run_checks = []
    for index, run in enumerate(runs):
        matches = captured[index] == run["reported_sent"] and not captured_unknown_flags[index]
        if not matches:
            problems.append(f"attack run {run['run_id']}: captured {captured[index]} matching packets "
                            f"({captured_unknown_flags[index]} with unknown flags) of {run['reported_sent']} sent")
        run_checks.append({**{k: run[k] for k in ("run_id", "protocol", "rate", "duration", "port", "state",
                                                   "reported_sent", "sent_rows", "run_json_sha256",
                                                   "activity_sha256")},
                           "start_server_epoch": run["start"], "stop_server_epoch": run["stop"],
                           "captured_matching_packets": captured[index],
                           "captured_unknown_flag_packets": captured_unknown_flags[index],
                           "sent_equals_captured": matches})

    records, feature_skips = extract_pcap(pcap, config)
    by_second = {math.floor(record.window_start): record for record in records}
    labels = label_windows(windows, runs, slack, boundary)
    mismatched = [second for second in labels
                  if (by_second[second].packet_count if second in by_second else 0) != windows.get(
                      second, {"total": 0})["total"]]
    if mismatched:
        problems.append(f"{len(mismatched)} windows where feature packet counts differ from labelled packets")
    valid = not problems

    scorer = None
    model_meta = None
    if model is not None:
        from ddos_detector.training import load_model, score_loaded_record
        pipeline, model_meta = load_model(model)
        scorer = lambda record: score_loaded_record(pipeline, model_meta, record)  # noqa: E731

    session_uuid = str(uuid.uuid4())
    counts = Counter()
    eligible_count = 0
    mismatched = set(mismatched)
    with (out / "windows.jsonl").open("x", encoding="utf-8") as handle:
        for second, (label, protocol, reason) in sorted(labels.items()):
            tally = windows.get(second) or _empty_tally()
            record = by_second.get(second)
            ineligible = []
            if reason:
                ineligible.append(reason)
            if record is not None and record.capped:
                ineligible.append("source cap reached")
            if second in mismatched:
                ineligible.append("packet count mismatch")
            if tally["tcp_flags_unknown"]:
                ineligible.append("unknown TCP flags")
            if not valid:
                ineligible.append("session not valid for scoring")
            score = None
            if (scorer and valid and record is not None and record.packet_count > 0 and not record.capped
                    and second not in mismatched):
                score = scorer({"capture_state": "valid", "capped": record.capped, "window_seconds": 1.0,
                                "feature_schema_version": FEATURE_SCHEMA_VERSION, "features": record.features})
            counts[label] += 1
            if label == "attack":
                counts[protocol] += 1
            if reason:
                counts[reason] += 1
            eligible_count += not ineligible
            row = {"window_id": f"{session_id}-{second}", "session_id": session_id, "session_uuid": session_uuid,
                   "role": role, "window_start": second, "label": label, "attack_protocol": protocol,
                   "exclusion_reason": reason, "eligible_for_policy": not ineligible,
                   "ineligible_reasons": ineligible,
                   "packet_count": tally["total"], "attack_packets": tally["attack"],
                   "benign_packets": tally["benign"], "unknown_packets": tally["unknown"],
                   "tcp_flags_unknown_packets": tally["tcp_flags_unknown"],
                   "attack_share": round(tally["attack"] / tally["total"], 6) if tally["total"] else None,
                   "features": record.features if record else None, "capped": record.capped if record else False,
                   "source_counts": [{"src": src, "proto": proto, **values}
                                     for (src, proto), values in sorted(tally["sources"].items())],
                   "score": score}
            handle.write(json.dumps(row, allow_nan=False) + "\n")

    from ddos_detector.training import source_revision, versions
    manifest = {
        "tool": "tools/lab_session_export.py", "tool_version": TOOL_VERSION,
        "session_id": session_id, "session_uuid": session_uuid, "role": role,
        "data_kind": "new_policy_lab_session_unreviewed",
        "decision": "issue #49 owner decision: new sessions, not replacements for S1/S2; original model and "
                    "threshold unchanged; no retraining; S3 untouched",
        "source_revision": source_revision(), "versions": {**versions(), "ddos_detector": _package_version()},
        "valid_for_scoring": valid, "problems": problems,
        "capture": {"file": Path(pcap).name, "sha256": file_sha256(pcap), "tcpdump_dropped": tcpdump_dropped,
                    "first_packet_epoch": first_ts, "last_packet_epoch": last_ts},
        "clock": clock_detail,
        "settings": {"victim_ip": config.victim_ip, "attacker": ATTACKER, "client": CLIENT,
                     "slack_seconds": slack, "boundary_seconds": boundary, "attack_share_threshold": ATTACK_SHARE,
                     "window_seconds": 1.0, "window_alignment": "unix_epoch",
                     "scope": "protected_server_inbound_ipv4_tcp_udp_icmp",
                     "size_definition": "ipv4_total_length_bytes",
                     "feature_schema_version": FEATURE_SCHEMA_VERSION},
        "schedule": schedule,
        "schedule_sha256": file_sha256(Path(attacker_dir) / "schedule.json") if schedule is not None else None,
        "attack_runs": run_checks, "retained_incomplete_attack_runs": retained,
        "client_run": client,
        "packet_labels": dict(reasons), "selection_skips": dict(skips), "feature_skips": dict(feature_skips),
        "window_counts": dict(counts), "windows_total": len(labels), "windows_eligible_for_policy": eligible_count,
        "window_packet_count_mismatches": len(mismatched),
        "model": None if model_meta is None else {"directory": str(model), "model_sha256": model_meta["model_sha256"],
                                                  "decision_threshold": model_meta["decision_threshold"]},
        "windows_file": "windows.jsonl", "windows_sha256": file_sha256(out / "windows.jsonl"),
        "policy_rules": {"ineligible_window_resets_streak": True,
                         "complete_sequence": "every second from first to last captured window; no subsetting"},
        "limits": ["Labels assume the lab network held only the server, client and attacker.",
                   "Captured-vs-sent matches source and protocol (SYN-only for TCP), not destination port.",
                   "Clock shifts use bracketed before/after samples; intra-session behavior assumes no "
                   "unobserved steps or excursions. Endpoint checks do not prove that assumption.",
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
    ap.add_argument("--session-id", required=True, help="e.g. policy-calibration-2026-11-27-a")
    ap.add_argument("--pcap", required=True, help="server capture")
    ap.add_argument("--attacker-dir", required=True, help="attacker results/<session-id> (schedule.json, scenarios/)")
    ap.add_argument("--client-run", required=True, help="the HTTP client's run UUID folder")
    ap.add_argument("--clock-before", help="tools/lab_clock_check.py output from before the session")
    ap.add_argument("--clock-after", help="tools/lab_clock_check.py output from after the session")
    ap.add_argument("--out", required=True, help="new export folder (must not exist)")
    ap.add_argument("--slack", type=float, default=2.5)
    ap.add_argument("--tcpdump-dropped", type=int, help="'packets dropped by kernel' from tcpdump")
    ap.add_argument("--model", help="trusted model folder (metadata.json + model.joblib)")
    args = ap.parse_args(argv)
    manifest = export(args.session_id, args.pcap, args.attacker_dir, args.client_run, args.out,
                      clock_before=args.clock_before, clock_after=args.clock_after, slack=args.slack,
                      tcpdump_dropped=args.tcpdump_dropped, model=args.model)
    print(json.dumps({"out": args.out, "valid_for_scoring": manifest["valid_for_scoring"],
                      "problems": manifest["problems"], "window_counts": manifest["window_counts"],
                      "windows_eligible_for_policy": manifest["windows_eligible_for_policy"]}, indent=2))
    return 0 if manifest["valid_for_scoring"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
