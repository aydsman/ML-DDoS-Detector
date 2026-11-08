"""Monitor-only pipeline: frames -> windows -> aggregate score -> JSONL log.

Scores every finished window with Ayden's saved model and appends one JSON line per
window to --log. It never blocks, never contacts a firewall and never changes
traffic. A window that cannot be scored (capped source counts, empty window) is
logged as not scored with the reason, never as benign or as zero.
"""
import argparse
import json
import sys
import time
from dataclasses import replace

from .config import Config
from .contracts import FEATURE_SCHEMA_VERSION
from .live import LivePipeline
from .pcap import PcapError, read_pcap
from .training import load_model, score_record


def window_record(record, window_seconds):
    """Build the dict score_record expects from a finished WindowRecord."""
    return {"capture_state": "valid", "capped": record.capped,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "window_seconds": window_seconds, "features": record.features}


class Monitor:
    """Score finished windows and write one log line each. Monitor-only."""

    def __init__(self, model_dir, log, window_seconds, clock=time.time, live=False):
        self.model_dir = model_dir
        self.log = log
        self.window_seconds = window_seconds
        self.clock = clock
        self.live = live  # only live windows have a meaningful processing delay
        self.windows = self.scored = self.not_scored = self.predicted_attack = 0
        self.max_delay = None

    def handle(self, record):
        started = self.clock()
        line = {"monitor_only": True, "window_start": record.window_start,
                "window_end": record.window_end, "packet_count": record.packet_count,
                "logged_at": started}
        # Delay since the window ended; replayed pcaps have historical times, so no delay.
        delay = round(started - record.window_end, 3) if self.live else None
        line["processing_delay_s"] = delay
        if delay is not None:
            self.max_delay = delay if self.max_delay is None else max(self.max_delay, delay)
        try:
            result = score_record(self.model_dir, window_record(record, self.window_seconds))
            line.update(scored=True, attack_score=result["attack_score"],
                        predicted_attack=result["predicted_attack"],
                        decision_threshold=result["decision_threshold"],
                        model_sha256=result["model_sha256"], data_kind=result["data_kind"])
            self.scored += 1
            self.predicted_attack += bool(result["predicted_attack"])
        except ValueError as exc:
            line.update(scored=False, not_scored_reason=str(exc))
            self.not_scored += 1
        line["scoring_s"] = round(self.clock() - started, 4)
        self.windows += 1
        self.log.write(json.dumps(line) + "\n")
        self.log.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ddos_detector.monitor",
        description="Monitor-only: score live or replayed windows and log the predictions.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Linux interface to capture on (needs root or CAP_NET_RAW)")
    source.add_argument("--replay", metavar="PCAP", help="feed a saved pcap through the same pipeline")
    parser.add_argument("--model", required=True, help="saved model folder (locally generated, trusted)")
    parser.add_argument("--log", required=True, help="JSONL file for per-window predictions (must not exist)")
    parser.add_argument("--victim", default=Config.victim_ip)
    parser.add_argument("--window", type=float, default=Config.window_seconds)
    parser.add_argument("--duration", type=float, help="stop a live capture after this many seconds")
    args = parser.parse_args(argv)
    if not args.window > 0:
        parser.error("--window must be positive")

    try:
        load_model(args.model)  # refuse to start on an unusable model, before any window is logged
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: model not usable: {exc}", file=sys.stderr)
        return 2
    pipeline = LivePipeline(replace(Config(), victim_ip=args.victim, window_seconds=args.window))
    try:
        log = open(args.log, "x", encoding="utf-8")  # never overwrite an earlier log
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    monitor = Monitor(args.model, log, args.window, live=bool(args.interface))
    exit_code = 0
    try:
        if args.replay:
            for record in pipeline.run(read_pcap(args.replay)):
                monitor.handle(record)
        else:
            from .capture import capture_frames
            try:
                for record in pipeline.run(capture_frames(args.interface, duration=args.duration),
                                           flush_at_end=False):
                    monitor.handle(record)
                if pipeline.status == "ok":
                    for record in pipeline.stop(pipeline.clock()):
                        monitor.handle(record)
            except KeyboardInterrupt:
                for record in pipeline.stop(pipeline.clock()):
                    monitor.handle(record)
    except (PcapError, OSError, NotImplementedError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        log.close()
    if pipeline.status != "ok":
        exit_code = 1
    print(f"windows: {monitor.windows}")
    print(f"scored: {monitor.scored}")
    print(f"not_scored: {monitor.not_scored}")
    print(f"predicted_attack: {monitor.predicted_attack}")
    if args.interface:
        print(f"max_processing_delay_s: {monitor.max_delay}")
    print("skipped: " + (", ".join(f"{k}={v}" for k, v in sorted(pipeline.skips.items())) or "none"))
    print(f"late_dropped: {pipeline.late_dropped}")
    print(f"status: {pipeline.status}")
    for gap in pipeline.gaps:
        print(f"unavailable since {gap.since}: {gap.reason} ({gap.discarded_windows} windows discarded)")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
