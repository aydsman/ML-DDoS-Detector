"""Reproduce Ali's internal-consistency audit of PR #29 at the pinned review head.

Reads JSON and the unmodified training loader from --snapshot. Raw dataset
files are neither read nor verified. This is review evidence, not an approval
or a general-purpose validator for future candidate schemas.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys

REVIEW_HEAD = "83e62f2ad99dd63f81a5a963183632786bae95e9"
LOADER_SHA256 = "e2227f0696859ccb01078b602f4542489ac8ff76b19b2a0f12aa6a75ff5c44a2"
ARTIFACT_HASHES = {
    "coverage.json": "a4bb763320ed2f86264f86d9a5843084c7cc35aadf14ed2e880fa4d866b9128e",
    "manifest.json": "be1be39a49ad0784c822d0ea15ba926a24e6ced4534072efeca82e13189eadda",
    "windows.json": "aced6b0466e092378771770dd1417d0c1ab01fca75c28d3b4449e9cb0612fe72",
}

FEATURES = ["packet_rate", "byte_rate", "syn_count", "syn_ack_ratio", "syn_no_ack_share",
            "pkt_size_mean", "pkt_size_std", "unique_src_ips", "src_ip_entropy",
            "tcp_share", "udp_share", "icmp_share"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate key in {path}: {key}")
            result[key] = value
        return result
    def invalid(value):
        raise ValueError(f"Nonfinite JSON constant in {path}: {value}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                      parse_constant=invalid)


def audit(snapshot):
    sample = snapshot / "docs/samples/cic-syn-0618-0620"
    artifacts = {name: {"sha256": digest(sample / name), "bytes": (sample / name).stat().st_size}
                 for name in ("manifest.json", "windows.json", "coverage.json")}
    if {name: value["sha256"] for name, value in artifacts.items()} != ARTIFACT_HASHES:
        raise ValueError("Inputs differ from the pinned PR #29 review; perform a new review instead")
    manifest, windows, coverage = [read_json(sample / name)
                                  for name in ("manifest.json", "windows.json", "coverage.json")]
    problems = []
    check_count = 0

    def check(condition, name, window_id=None):
        nonlocal check_count
        check_count += 1
        if not condition:
            problems.append({"check": name, "window_id": window_id})

    def equal(a, b):
        return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-6)

    check(manifest["feature_names"] == FEATURES, "ordered feature names")
    check(manifest["feature_schema_version"] == "1", "feature schema version")
    check(manifest["window_alignment"] == "unix_epoch" and manifest["window_seconds"] == 1,
          "one-second epoch grid")
    check(manifest["scope"] == "protected_server_inbound_ipv4_tcp_udp_icmp", "capture scope")
    check(manifest["size_definition"] == "ipv4_total_length_bytes", "IP byte definition")
    check(manifest["data_kind"] == "candidate_unreviewed_packet_windows", "candidate not reviewed")
    check(all(v is None for v in manifest["review_refs"].values()), "no claimed review references")
    check(all(run["split"] is None for run in manifest["runs"].values()), "no assigned training splits")
    check(len(manifest["runs"]) == 1, "one reported run")
    for capture_id, capture in manifest["captures"].items():
        check(bool(re.fullmatch(r"[0-9a-fA-F]{64}", capture["sha256"])), "reported capture hash syntax", capture_id)
        check(bool(capture["label_metadata_reference"]), "reported metadata reference", capture_id)
    assigned = [cid for run in manifest["runs"].values() for cid in run["capture_ids"]]
    check(set(assigned) == set(manifest["captures"]), "run covers declared captures")
    check(len(assigned) == len(set(assigned)), "capture assignment unique")

    interval = [datetime.fromisoformat(s).timestamp() for s in coverage["attack_interval_pcap_utc"]]
    ids, run_windows = set(), set()
    totals, labels, reasons, rule_reasons, capture_states = Counter(), Counter(), Counter(), Counter(), Counter()
    captures = defaultdict(Counter)
    boundary_rows, attacks, mismatched_counts = [], [], 0
    starts = []
    protocol_totals = Counter()
    for row in windows:
        wid = row["window_id"]
        check(wid not in ids, "unique window ID", wid)
        ids.add(wid)
        start, end = row["window_start"], row["window_end"]
        check(start == math.floor(start) and equal(end - start, 1), "window on epoch grid", wid)
        check((row["run_id"], start) not in run_windows, "unique run/window", wid)
        run_windows.add((row["run_id"], start))
        starts.append(int(start))
        run = manifest["runs"].get(row["run_id"])
        check(run is not None and row["capture_id"] in run["capture_ids"], "capture/run reference", wid)
        check(wid == f"{row['run_id']}-{int(start)}", "encoded window identity", wid)
        n, a, u = [row[name] for name in ("packet_count", "attack_labelled_packets", "unknown_packets")]
        check(all(type(v) is int and v >= 0 for v in (n, a, u)), "nonnegative integer counts", wid)
        check(a + u == n, "strict candidate counts partition selected packets", wid)
        mismatched_counts += a + u != n
        totals.update(packet_count=n, attack_labelled_packets=a, unknown_packets=u)
        capture_states[row["capture_state"]] += 1
        check(row["capture_state"] in ("valid", "failed", "missing", "uncertain"), "capture state enum", wid)
        check(all(type(row[field]) is bool for field in ("boundary", "capped", "inside_attack_interval")),
              "explicit flags", wid)
        check(row["inside_attack_interval"] == (interval[0] <= start and end <= interval[1]),
              "inside flag matches reported interval only", wid)

        # Literal independent count/exclusion contract; no production selector used.
        if row["capture_state"] != "valid": reason = "unavailable"
        elif row["capped"]: reason = "capped"
        elif u: reason = "unknown"
        elif row["boundary"]: reason = "boundary"
        elif n == 0: reason = "empty"
        elif a * 5 >= n * 4: reason = None
        elif a: reason = "mixed"
        elif row["inside_attack_interval"]: reason = "interval_without_attack"
        else: reason = None
        expected = "excluded" if reason else ("attack" if a else "benign")
        check(row["label"] == expected, "independent label decision", wid)
        labels[row["label"]] += 1
        if reason:
            rule_reasons[reason] += 1
            reasons[row["label_reason"]] += 1
        if row["boundary"]:
            boundary_rows.append({"window_id": wid, "capture_id": row["capture_id"],
                                  "label": row["label"], "unknown_packets": u,
                                  "first_exclusion_reason": reason})
        features = row["features"]
        check(set(features) == set(FEATURES), "exact feature names", wid)
        check(all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in features.values()),
              "finite nonnegative feature values", wid)
        check(equal(features["packet_rate"], n), "rate/count equality", wid)
        if n:
            check(equal(features["byte_rate"], features["pkt_size_mean"] * n), "bytes/mean equality", wid)
            check(20 <= features["pkt_size_mean"] <= 65535, "IPv4 mean size bounds", wid)
        check(equal(features["byte_rate"], round(features["byte_rate"])), "integral byte sum", wid)
        check(equal(sum(features[p + "_share"] for p in ("tcp", "udp", "icmp")), 1), "protocol share sum", wid)
        for p in ("tcp", "udp", "icmp"):
            share = features[p + "_share"]
            check(0 <= share <= 1 and equal(share * n, round(share * n)), "protocol count integrality", wid)
            protocol_totals[p] += round(share * n)
        check(0 <= features["syn_count"] <= features["tcp_share"] * n + 1e-6 and
              features["syn_count"] == int(features["syn_count"]), "SYN count bounds", wid)
        sources = features["unique_src_ips"]
        check(sources == int(sources) and 1 <= sources <= n, "source count bounds", wid)
        check(features["src_ip_entropy"] <= math.log2(sources) + 1e-9, "entropy upper bound", wid)
        check(0 <= features["syn_no_ack_share"] <= 1, "SYN share bounds", wid)
        # In default strict mode all ICMP lacks a 5-tuple and must remain unknown.
        if coverage["icmp_as_protocol0"] is False:
            check(u + 1e-6 >= features["icmp_share"] * n, "strict ICMP is unknown", wid)
        captures[row["capture_id"]].update(windows=1, packets=n, attack_packets=a, unknown_packets=u,
                                          attack_windows=row["label"] == "attack",
                                          excluded_windows=row["label"] == "excluded")
        if row["label"] == "attack":
            attacks.append({"window_id": wid, "packet_count": n, "attack_labelled_packets": a,
                            "unknown_packets": u, "syn_count": features["syn_count"],
                            "syn_packet_fraction": features["syn_count"] / n,
                            "tcp_packets": round(features["tcp_share"] * n),
                            "udp_packets": round(features["udp_share"] * n),
                            "boundary": row["boundary"], "inside_reported_interval": row["inside_attack_interval"]})
    check(starts == sorted(starts), "windows sorted")
    check(coverage["windows_total"] == len(windows), "coverage window total")
    check(coverage["windows_label_counts"] == dict(labels), "coverage label counts")
    check(coverage["windows_by_exclusion_reason"] == dict(reasons), "coverage exclusion counts")
    check(coverage["benign_windows_available"] == labels["benign"], "coverage benign count")
    check(coverage["windows_packet_count_mismatch"] == mismatched_counts, "reported zero mismatch consistent with stored partitions")
    packet_reasons = coverage["packet_label_reasons"]
    check(sum(packet_reasons.values()) == totals["packet_count"], "reason counts total selected packets")
    check(packet_reasons["matched_attack_flow"] == totals["attack_labelled_packets"], "reason attack subtotal")
    check(sum(v for k, v in packet_reasons.items() if k != "matched_attack_flow") == totals["unknown_packets"],
          "reason unknown subtotal")
    boundaries_excluded = all(r["label"] == "excluded" for r in boundary_rows)
    check(boundaries_excluded, "all boundary flags excluded")
    gaps = [{"start": a + 1, "end": b, "seconds": b - a - 1}
            for a, b in zip(starts, starts[1:]) if b > a + 1]

    # Exercise the actual loader on unchanged artifacts, without fake review refs/splits.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    from ddos_detector import training_data
    if digest(Path(training_data.__file__)) != LOADER_SHA256:
        raise ValueError("Imported training loader differs from the pinned review")
    prepare_data = training_data.prepare_data
    loader = {"input_modified": False, "source_sha256": LOADER_SHA256, "rejected": False, "error": None}
    try:
        prepare_data(sample / "windows.json", sample / "manifest.json")
    except ValueError as exc:
        loader.update(rejected=True, error=str(exc))
    check(loader["rejected"] and loader["error"] == "data_kind must be synthetic or reviewed_packet_windows",
          "actual loader rejects candidate kind without fabricated approvals")

    return {"audit_scope": "Committed candidate JSON internal consistency only; raw PCAP/CSV unavailable",
            "audited_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": {"repository": "aydsman/ML-DDoS-Detector", "pull_request": 29,
                       "reviewed_head": REVIEW_HEAD},
            "audit_script_sha256": digest(Path(__file__)),
            "artifacts": artifacts, "checks_performed": check_count,
            "internal_consistency_passed": not problems, "problems": problems,
            "raw_input_hashes_recomputed": False, "ground_truth_independently_verified": False,
            "feature_parity_independently_verified": False, "timezone_verified": False,
            "training_approved": False, "totals": dict(totals), "window_count": len(windows),
            "labels": dict(labels), "reported_exclusion_reasons": dict(reasons),
            "independent_first_exclusion_reasons": dict(rule_reasons),
            "capture_states_as_supplied": dict(capture_states), "protocol_counts_from_feature_shares": dict(protocol_totals),
            "boundary_count": len(boundary_rows), "boundary_rows": boundary_rows,
            "candidate_attack_windows": attacks, "capture_counts": dict(captures),
            "manifest_run_count": len(manifest["runs"]), "manifest_capture_count": len(manifest["captures"]),
            "assigned_splits": {key: run["split"] for key, run in manifest["runs"].items()},
            "grid_observation": {"start": min(starts), "end": max(starts) + 1,
                                 "span_seconds": max(starts) - min(starts) + 1,
                                 "unrepresented_seconds": sum(g["seconds"] for g in gaps), "gaps": gaps,
                                 "interpretation": "Absent rows do not establish quiet intervals or capture loss; default aggregator omits empty rows."},
            "loader_check": loader,
            "limits": ["Arithmetic consistency does not reproduce raw packet/flow matching or verify supplied capture_state.",
                       "Reported packet reasons are aggregate totals, not frame/CSV-row join evidence.",
                       "Eight candidate attack labels depend on supplied CSV/offset labels; SYN features alone do not establish ground truth.",
                       "Boundary flags were counted, not recomputed from inaccessible raw piece bounds.",
                       "No independent benign examples, independent runs, or reviewed split are supplied."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.snapshot.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"output": str(args.output.resolve()), "output_sha256": digest(args.output),
                      "internal_consistency_passed": result["internal_consistency_passed"],
                      "checks_performed": result["checks_performed"], "problems": result["problems"]}, indent=2))
    raise SystemExit(0 if result["internal_consistency_passed"] else 1)
