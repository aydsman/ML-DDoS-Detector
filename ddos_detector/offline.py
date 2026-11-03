"""Offline entry point: saved pcap -> verified-format window feature records."""
import argparse
import csv
import json
import sys
from dataclasses import replace

from .aggregate import WindowAggregator
from .config import FEATURE_NAMES, Config
from .frames import frame_to_packet
from .normalize import SkipCounter
from .pcap import PcapError, read_pcap

COLUMNS = ["window_start", "window_end", *FEATURE_NAMES,
           "packet_count", "capped", "untracked_source_packets"]


def extract_pcap(path, config=None):
    """Return (records, skips) for one pcap: WindowRecords and a SkipCounter."""
    records, skips, _ = _extract(path, config or Config())
    return records, skips


def _extract(path, config):
    skips = SkipCounter()
    aggregator = WindowAggregator(config)
    records = []
    for ts, frame in read_pcap(path):
        packet = frame_to_packet(frame, ts, config.victim_ip, skips).packet
        records += aggregator.advance(ts) if packet is None else aggregator.add(packet)
    records += aggregator.flush()
    return records, skips, aggregator.late_dropped


def record_row(record):
    return {"window_start": record.window_start, "window_end": record.window_end,
            **record.features, "packet_count": record.packet_count,
            "capped": record.capped,
            "untracked_source_packets": record.untracked_source_packets}


def write_records(records, out):
    """Write records to out as CSV or JSONL, chosen by file extension."""
    rows = [record_row(r) for r in records]
    if out.lower().endswith(".csv"):
        with open(out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
    elif out.lower().endswith(".jsonl"):
        with open(out, "w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
    else:
        raise ValueError("--out must end in .csv or .jsonl")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ddos_detector.offline",
        description="Extract per-window features from a classic Ethernet pcap.")
    parser.add_argument("pcap")
    parser.add_argument("--victim", default=Config.victim_ip, help="inbound = destination IPv4")
    parser.add_argument("--window", type=float, default=Config.window_seconds, help="seconds")
    parser.add_argument("--out", help="write records to this .csv or .jsonl file")
    args = parser.parse_args(argv)
    if args.out and not args.out.lower().endswith((".csv", ".jsonl")):
        parser.error("--out must end in .csv or .jsonl")
    if not args.window > 0:
        parser.error("--window must be positive")

    config = replace(Config(), victim_ip=args.victim, window_seconds=args.window)
    try:
        records, skips, late = _extract(args.pcap, config)
    except (PcapError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"windows: {len(records)}")
    print(f"packets: {sum(r.packet_count for r in records)}")
    print("skipped: " + (", ".join(f"{k}={v}" for k, v in sorted(skips.items())) or "none"))
    print(f"late_dropped: {late}")
    if args.out:
        write_records(records, args.out)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
