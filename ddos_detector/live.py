"""Live pipeline: raw Ethernet frames -> WindowRecords, plus a replay/live CLI."""
import argparse
import csv
import json
import sys
import time
from dataclasses import dataclass, replace

from .aggregate import WindowAggregator
from .config import Config
from .frames import frame_to_packet
from .normalize import SkipCounter
from .offline import COLUMNS, record_row
from .pcap import PcapError, read_pcap


@dataclass(frozen=True)
class CaptureGap:
    """Measurements that could not be taken; never to be read as zero traffic."""
    since: float | None  # start of the earliest discarded window, else the last timestamp seen
    reason: str
    discarded_windows: int  # open windows dropped because their coverage was incomplete


class LivePipeline:
    """Feed (ts, frame) pairs in, get finished WindowRecords out.

    Uses the same frame parser, skip counter and WindowAggregator as the offline
    path, so identical frames give identical records. Time advances with packet
    timestamps; tick(now) additionally advances it on the clock so a quiet link
    still closes windows. If the source fails, status becomes "unavailable":
    open windows are discarded (their coverage is incomplete), nothing is
    zero-filled, and the failure is recorded in gaps.
    """

    def __init__(self, config=Config(), clock=time.time, emit_empty=False):
        self.config = config
        self.clock = clock
        self.skips = SkipCounter()
        self.aggregator = WindowAggregator(config, emit_empty)
        self.status = "ok"  # or "unavailable"
        self.gaps = []
        self.partial_windows_discarded = 0  # open windows left unfinished by stop()
        self._last_ts = None

    @property
    def late_dropped(self):
        return self.aggregator.late_dropped

    def feed(self, ts, frame):
        """Process one frame; return the windows it finalizes."""
        if self.status != "ok":
            raise RuntimeError("capture is unavailable; the pipeline accepts no more frames")
        self._last_ts = ts if self._last_ts is None else max(self._last_ts, ts)
        result = frame_to_packet(frame, ts, self.config.victim_ip, self.skips)
        if result.packet is None:
            # A filtered frame (ARP, outbound, other destinations) still shows time has
            # reached ts, so finished windows close even while unselected traffic keeps the link busy.
            return self.aggregator.advance(ts)
        return self.aggregator.add(result.packet)

    def tick(self, now=None):
        """Advance time without a frame; return the windows now past their grace."""
        if self.status != "ok":
            return []
        return self.aggregator.advance(self.clock() if now is None else now)

    def run(self, source, flush_at_end=True):
        """Yield records from an iterable of (ts, frame); None items mean a receive timeout.

        Exhausting the source is a normal end of input (open windows are
        flushed unless flush_at_end is False, as for a live capture that was
        merely stopped). An exception from the source marks the capture
        unavailable; a PcapError is bad input, not a capture failure, and
        propagates.
        """
        try:
            for item in source:
                yield from (self.tick() if item is None else self.feed(*item))
        except PcapError:
            raise
        except Exception as exc:
            self.fail(f"{type(exc).__name__}: {exc}")
            return
        if flush_at_end:
            yield from self.flush()

    def flush(self):
        """End of input: finalize every open window."""
        return self.aggregator.flush() if self.status == "ok" else []

    def stop(self, now=None):
        """Live stop: finalize windows that ended by now; drop the unfinished one."""
        if self.status != "ok":
            return []
        now = self.clock() if now is None else now
        records = self.aggregator.advance(now + self.config.grace_seconds)
        self.partial_windows_discarded = len(self.aggregator._open)
        self.aggregator._open.clear()
        return records

    def fail(self, reason):
        """Mark the capture unavailable and discard windows with incomplete coverage."""
        open_windows = self.aggregator._open
        since = (min(open_windows) * self.config.window_seconds if open_windows
                 else self._last_ts)
        self.gaps.append(CaptureGap(since, reason, len(open_windows)))
        open_windows.clear()
        self.status = "unavailable"


class _RecordWriter:
    """Incremental CSV/JSONL writer, so records survive an interrupted live run."""

    def __init__(self, path):
        self.csv = path.lower().endswith(".csv")
        self.file = open(path, "w", newline="")
        if self.csv:
            self.writer = csv.DictWriter(self.file, fieldnames=COLUMNS)
            self.writer.writeheader()

    def write(self, record):
        row = record_row(record)
        if self.csv:
            self.writer.writerow(row)
        else:
            self.file.write(json.dumps(row) + "\n")
        self.file.flush()

    def close(self):
        self.file.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m ddos_detector.live",
        description="Run the live feature pipeline on an interface, or replay a saved pcap.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Linux interface to capture on (needs root or CAP_NET_RAW)")
    source.add_argument("--replay", metavar="PCAP", help="feed a saved pcap through the same pipeline")
    parser.add_argument("--victim", default=Config.victim_ip)
    parser.add_argument("--window", type=float, default=Config.window_seconds)
    parser.add_argument("--out", help="write records to this .csv or .jsonl file")
    parser.add_argument("--duration", type=float, help="stop a live capture after this many seconds")
    args = parser.parse_args(argv)
    if args.out and not args.out.lower().endswith((".csv", ".jsonl")):
        parser.error("--out must end in .csv or .jsonl")
    if not args.window > 0:
        parser.error("--window must be positive")

    pipeline = LivePipeline(replace(Config(), victim_ip=args.victim, window_seconds=args.window))
    writer = _RecordWriter(args.out) if args.out else None
    windows = packets = 0

    def emit(records):
        nonlocal windows, packets
        for record in records:
            windows += 1
            packets += record.packet_count
            if writer:
                writer.write(record)

    exit_code = 0
    try:
        if args.replay:
            emit(pipeline.run(read_pcap(args.replay)))
        else:
            from .capture import capture_frames
            try:
                emit(pipeline.run(capture_frames(args.interface, duration=args.duration),
                                  flush_at_end=False))
                if pipeline.status == "ok":
                    emit(pipeline.stop(pipeline.clock()))
            except KeyboardInterrupt:
                emit(pipeline.stop(pipeline.clock()))
    except (PcapError, OSError, NotImplementedError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if writer:
            writer.close()
    if pipeline.status != "ok":
        exit_code = 1
    print(f"windows: {windows}")
    print(f"packets: {packets}")
    print("skipped: " + (", ".join(f"{k}={v}" for k, v in sorted(pipeline.skips.items())) or "none"))
    print(f"late_dropped: {pipeline.late_dropped}")
    print(f"status: {pipeline.status}")
    for gap in pipeline.gaps:
        print(f"unavailable since {gap.since}: {gap.reason} ({gap.discarded_windows} windows discarded)")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
