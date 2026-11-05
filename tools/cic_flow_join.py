"""Join CIC-DDoS2019 flow-CSV labels to PCAP packets and build candidate windows (issue #3).

Read-only on inputs; writes only new files under --out-dir (never overwrites).

Two stages, run together:

1. Timestamp-offset test.  CSV flow start times are compared with PCAP packets for each
   candidate whole-hour offset: a flow start "matches" when a packet with the same
   protocol, both addresses and both ports exists at exactly CSV time + offset
   (integer microseconds).  The offset is reported, never assumed; the join refuses to
   run on an offset with no matches.
2. Packet labelling and windowing.  Each in-scope inbound packet (IPv4 to --victim, valid
   header/Total Length, TCP/UDP/ICMP) is matched to a CSV flow by 5-tuple (either flow
   direction) and by the flow's [start, start + duration] interval.  Labels:
     attack   - matched only to flows labelled as an attack
     unknown  - unmatched, ambiguous (several flows with different labels), non-first
                fragment / ICMP / any packet without a usable 5-tuple, or matched to a
                CSV BENIGN flow (the CSV label alone is not independent benign evidence)
   Features come from the package's own extractor (ddos_detector) over the same pieces
   in order, so they use the live feature definitions.  Window packet counts from the
   independent labelling pass must equal the extractor's, otherwise the window is
   marked capture_state "uncertain".

    python -m tools.cic_flow_join --csv Syn.csv --pieces P1 P2 P3 --victim 192.168.50.1 \
        --attack-label Syn --offset-hours 4 --out-dir results/cic-syn-0618-0620
"""
import argparse
import calendar
import collections
import csv
import datetime
import hashlib
import json
import math
import os
import struct
import sys

from ddos_detector.aggregate import WindowAggregator
from ddos_detector.config import FEATURE_NAMES, Config
from ddos_detector.frames import frame_to_packet
from ddos_detector.normalize import SkipCounter
from ddos_detector.pcap import read_pcap

TOOL_VERSION = "1"
HOUR_US = 3600 * 1_000_000
MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
          b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}


def csv_us(text):
    """'YYYY-MM-DD HH:MM:SS[.ffffff]' as integer microseconds, read as if it were UTC."""
    day, clock = text.strip().split(" ")
    y, mo, d = map(int, day.split("-"))
    hh, mm, ss = clock.split(":")
    whole, _, frac = ss.partition(".")
    return (calendar.timegm((y, mo, d, int(hh), int(mm), int(whole), 0, 0, 0)) * 1_000_000
            + int((frac + "000000")[:6]))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 22), b""):
            digest.update(block)
    return digest.hexdigest()


def load_flows(path):
    """CSV rows -> list of dicts (start_us, duration_us, label, key, inbound)."""
    flows = []
    with open(path, newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.reader(handle)
        ix = {c.strip(): i for i, c in enumerate(next(reader))}
        for row in reader:
            start = csv_us(row[ix["Timestamp"]])
            flows.append({
                "start": start, "end": start + int(float(row[ix["Flow Duration"]])),
                "label": row[ix["Label"]].strip(),
                "key": (row[ix["Source IP"]].strip(), int(row[ix["Source Port"]]),
                        row[ix["Destination IP"]].strip(), int(row[ix["Destination Port"]]),
                        int(row[ix["Protocol"]]))})
    return flows


def iter_packets(path):
    """Yield (timestamp_us, frame_bytes) from a classic pcap, stdlib only."""
    with open(path, "rb") as handle:
        header = handle.read(24)
        endian, scale = MAGICS[header[:4]]
        rec = struct.Struct(endian + "IIII")
        per_second = 1_000_000_000 // scale  # fractional units per microsecond
        while True:
            raw = handle.read(16)
            if len(raw) < 16:
                return
            sec, frac, incl, _ = rec.unpack(raw)
            data = handle.read(incl)
            if len(data) < incl:
                return
            yield sec * 1_000_000 + (frac * 1000 // per_second if scale == 1_000_000_000
                                     else frac), data


def packet_scope(data, victim):
    """(src, sport, proto, dport, fragment, ok) for in-scope inbound IPv4, else None."""
    if len(data) < 34 or data[12:14] != b"\x08\x00":
        return None
    ihl = (data[14] & 0x0F) * 4
    if data[14] >> 4 != 4 or ihl < 20 or len(data) < 14 + ihl:
        return None
    if struct.unpack(">H", data[16:18])[0] < ihl:
        return None
    proto = data[23]
    if proto not in (1, 6, 17):
        return None
    dst = ".".join(map(str, data[30:34]))
    if dst != victim:
        return None
    src = ".".join(map(str, data[26:30]))
    fragment = bool(struct.unpack(">H", data[20:22])[0] & 0x1FFF)
    sport = dport = None
    if proto in (6, 17) and not fragment and len(data) >= 14 + ihl + 4:
        sport, dport = struct.unpack(">HH", data[14 + ihl:14 + ihl + 4])
    return src, sport, dst, dport, proto


def offset_test(flows, pieces, candidate_hours, victim):
    """Count flow starts that equal a packet (same 5-tuple, same microsecond) at each offset."""
    wanted = {}
    for flow in flows:
        wanted.setdefault(flow["key"], []).append(flow["start"])
    index = {h: {k: {s + h * HOUR_US for s in v} for k, v in wanted.items()}
             for h in candidate_hours}
    hits = {h: set() for h in candidate_hours}
    for piece in pieces:
        for ts, data in iter_packets(piece):
            if len(data) < 38 or data[12:14] != b"\x08\x00" or data[23] not in (6, 17):
                continue
            ihl = (data[14] & 0x0F) * 4
            if len(data) < 14 + ihl + 4 or struct.unpack(">H", data[20:22])[0] & 0x1FFF:
                continue
            sport, dport = struct.unpack(">HH", data[14 + ihl:14 + ihl + 4])
            key = (".".join(map(str, data[26:30])), sport, ".".join(map(str, data[30:34])),
                   dport, data[23])
            for h in candidate_hours:
                starts = index[h].get(key)
                if starts and ts in starts:
                    hits[h].add((key, ts))
    return {h: len(v) for h, v in hits.items()}


def label_windows(flows, pieces, victim, attack_labels, offset_us, icmp_as_protocol0=False):
    """Per-second counts: selected / attack / unknown, plus reason counters."""
    by_key = collections.defaultdict(list)
    for flow in flows:
        item = (flow["start"] + offset_us, flow["end"] + offset_us, flow["label"])
        a, sp, b, dp, proto = flow["key"]
        by_key[flow["key"]].append(item)
        by_key[(b, dp, a, sp, proto)].append(item)  # packets of the reverse direction
    stats = collections.defaultdict(lambda: collections.Counter())
    reasons = collections.Counter()
    for piece in pieces:
        for ts, data in iter_packets(piece):
            scope = packet_scope(data, victim)
            if scope is None:
                continue
            src, sport, dst, dport, proto = scope
            if proto == 1 and icmp_as_protocol0:
                # Inferred convention, not documented by the dataset: ICMP flows appear as
                # Protocol 0 with ports 0/0.  Opt-in only; see coverage.json for the counts.
                sport, dport, proto = 0, 0, 0
            second = ts // 1_000_000
            counter = stats[second]
            counter["selected"] += 1
            if sport is None:
                counter["unknown"] += 1
                reasons["no_5_tuple(icmp_or_non_first_fragment_or_short)"] += 1
                continue
            labels = {lab for s, e, lab in by_key.get((src, sport, dst, dport, proto), ())
                      if s <= ts <= e}
            if not labels:
                counter["unknown"] += 1
                reasons["no_matching_flow_interval"] += 1
            elif len(labels) > 1:
                counter["unknown"] += 1
                reasons["ambiguous_labels"] += 1
            elif labels <= attack_labels:
                counter["attack"] += 1
                reasons["matched_attack_flow"] += 1
            else:
                counter["unknown"] += 1
                reasons["matched_csv_label_" + next(iter(labels)) + "_not_independently_verified"] += 1
    return stats, reasons


def extract_chain(pieces, config):
    """The package's own extractor over several pieces as one continuous capture."""
    skips, aggregator, records = SkipCounter(), WindowAggregator(config), []
    for piece in pieces:
        for ts, frame in read_pcap(piece):
            packet = frame_to_packet(frame, ts, config.victim_ip, skips).packet
            records += aggregator.advance(ts) if packet is None else aggregator.add(packet)
    records += aggregator.flush()
    return records


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csv", required=True)
    ap.add_argument("--pieces", nargs="+", required=True)
    ap.add_argument("--victim", required=True)
    ap.add_argument("--attack-label", action="append", required=True)
    ap.add_argument("--offset-hours", type=int, required=True,
                    help="CSV time + this many hours = PCAP epoch time; must show matches")
    ap.add_argument("--icmp-as-protocol0", action="store_true",
                    help="match ICMP packets to CSV Protocol-0 flows (inferred, off by default)")
    ap.add_argument("--candidate-hours", type=int, nargs="*", default=list(range(-6, 7)))
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    if os.path.exists(args.out_dir):
        sys.exit(f"refusing to overwrite {args.out_dir}")

    flows = load_flows(args.csv)
    candidates = sorted(set(args.candidate_hours) | {args.offset_hours})
    matches = offset_test(flows, args.pieces, candidates, args.victim)
    if not matches[args.offset_hours]:
        sys.exit(f"no flow start matches a packet at offset {args.offset_hours} h: {matches}")

    config = Config(victim_ip=args.victim)
    stats, reasons = label_windows(flows, args.pieces, args.victim, set(args.attack_label),
                                   args.offset_hours * HOUR_US,
                                   args.icmp_as_protocol0)
    records = extract_chain(args.pieces, config)

    attack_flows = [f for f in flows if f["label"] in args.attack_label]
    interval = (min(f["start"] for f in attack_flows) + args.offset_hours * HOUR_US,
                max(f["end"] for f in attack_flows) + args.offset_hours * HOUR_US)
    piece_bounds = []
    for piece in args.pieces:
        stamps = [ts for ts, _ in iter_packets(piece)]
        piece_bounds.append((os.path.basename(piece), min(stamps), max(stamps)))
    first_second = min(r.window_start for r in records)
    last_second = max(r.window_start for r in records)

    windows, mismatches = [], 0
    for record in records:
        second = int(record.window_start)
        c = stats.get(second, collections.Counter())
        selected, attack, unknown = c["selected"], c["attack"], c["unknown"]
        valid = selected == record.packet_count
        mismatches += not valid
        start_us, end_us = second * 1_000_000, (second + 1) * 1_000_000
        edge = any(lo // 1_000_000 == second or hi // 1_000_000 == second
                   for _, lo, hi in piece_bounds) or second in (first_second, last_second)
        capture = next((name for name, lo, hi in piece_bounds if start_us <= hi), piece_bounds[-1][0])
        inside = interval[0] <= start_us and end_us <= interval[1]
        if not valid:
            label, why = "excluded", "independent packet count differs from extractor"
        elif record.capped:
            label, why = "excluded", "source tracking capped"
        elif unknown:
            label, why = "excluded", "contains packets with unknown or unverified labels"
        elif edge:
            label, why = "excluded", "window touches a piece or run edge"
        elif selected and attack / selected >= 0.8:
            label, why = "attack", "all selected packets matched attack-labelled CSV flows"
        else:
            label, why = "excluded", "mixed or empty"
        windows.append({
            "window_id": f"{args.run_id}-{second}", "run_id": args.run_id,
            "capture_id": capture,
            "window_start": float(second), "window_end": float(second + 1),
            "features": {n: record.features[n] for n in FEATURE_NAMES},
            "packet_count": record.packet_count, "attack_labelled_packets": attack,
            "unknown_packets": unknown,
            "capture_state": "valid" if valid else "uncertain",
            "capped": bool(record.capped), "boundary": edge,
            "inside_attack_interval": inside, "label": label, "label_reason": why})

    os.makedirs(args.out_dir)
    manifest = {
        "data_kind": "candidate_unreviewed_packet_windows",
        "status_note": ("NOT reviewed and NOT usable for training: one run, no verified "
                        "benign windows, split unassigned. Same structure as docs/training.md."),
        "feature_schema_version": "1", "feature_names": FEATURE_NAMES,
        "window_seconds": 1.0, "window_alignment": "unix_epoch",
        "scope": "protected_server_inbound_ipv4_tcp_udp_icmp",
        "size_definition": "ipv4_total_length_bytes",
        "review_refs": {"labels": None, "splits": None, "feature_parity": None},
        "runs": {args.run_id: {"split": None, "capture_ids": [n for n, _, _ in piece_bounds]}},
        "captures": {os.path.basename(p): {
            "sha256": sha256_file(p),
            "label_metadata_reference": f"{os.path.basename(args.csv)} (CIC flow CSV), "
                                        f"csv sha256 {sha256_file(args.csv)}"} for p in args.pieces},
    }
    coverage = {
        "tool": "tools/cic_flow_join.py", "tool_version": TOOL_VERSION,
        "python": sys.version.split()[0],
        "run_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "csv_flows": len(flows), "victim": args.victim,
        "attack_labels": args.attack_label,
        "offset_hours_used": args.offset_hours,
        "icmp_as_protocol0": args.icmp_as_protocol0,
        "offset_test_flow_starts_matching_a_packet_exactly": {str(h): n for h, n in matches.items()},
        "attack_interval_pcap_utc": [datetime.datetime.fromtimestamp(
            t / 1e6, datetime.timezone.utc).isoformat() for t in interval],
        "packet_label_reasons": dict(reasons),
        "windows_total": len(windows),
        "windows_label_counts": dict(collections.Counter(w["label"] for w in windows)),
        "windows_packet_count_mismatch": mismatches,
        "windows_by_exclusion_reason": dict(collections.Counter(
            w["label_reason"] for w in windows if w["label"] == "excluded")),
        "benign_windows_available": 0 if not any(w["label"] == "benign" for w in windows) else None,
        "limitations": [
            "CSV labels are the dataset's own; only packet-to-flow consistency is checked here.",
            "Packets matched to CSV BENIGN flows count as unknown, not verified benign.",
            "All pieces come from one capture run: no independent runs can be assigned.",
        ]}
    for name, obj in (("windows.json", windows), ("manifest.json", manifest),
                      ("coverage.json", coverage)):
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8") as handle:
            json.dump(obj, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps({k: coverage[k] for k in (
        "offset_test_flow_starts_matching_a_packet_exactly", "windows_total",
        "windows_label_counts", "windows_packet_count_mismatch", "packet_label_reasons")},
        indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
