"""Streaming window aggregation shared by offline PCAP replay and live capture."""
import math
from dataclasses import dataclass

from .config import FEATURE_NAMES, Config
from .contracts import FEATURE_SCHEMA_VERSION, feature_vector
from .features import WindowAccumulator


@dataclass(frozen=True)
class SourceCount:
    source_ip: str
    protocol: str
    packets: int
    syn_packets: int = 0


@dataclass(frozen=True)
class WindowRecord:
    window_start: float
    window_end: float  # exclusive
    vector: tuple  # the 12 features in FEATURE_NAMES order
    packet_count: int
    # Diagnostics, kept outside the model vector.
    capped: bool = False
    untracked_source_packets: int = 0  # packets from sources beyond the per-window cap
    source_counts: tuple[SourceCount, ...] = ()  # diagnostics, never model inputs

    @property
    def features(self):
        return dict(zip(FEATURE_NAMES, self.vector))


class WindowAggregator:
    """Turn packets into finished WindowRecords with bounded state.

    Windows are epoch-aligned, start-inclusive and end-exclusive. A window is
    finalized once the newest timestamp seen (or advance(now)) reaches its end
    plus grace_seconds; packets that then arrive for it are dropped and counted
    in late_dropped, so a finished window never changes. Out-of-order packets
    inside the grace period go to their own open window. Open windows are
    limited to those within grace of the newest timestamp, at most
    ceil(grace/window)+1; a jump forward in time finalizes older windows first.

    Windows with no packets are not emitted by default: the contract excludes
    empty windows from training and inference, and only the capture layer
    knows whether the gap was measured. emit_empty=True zero-fills them
    (packet_count 0) between emitted windows; a long time jump then emits one
    record per skipped window.

    Records come out in increasing window order from add(), advance(), flush().
    """

    def __init__(self, config=Config(), emit_empty=False):
        self.window_seconds = config.window_seconds
        self.grace_seconds = config.grace_seconds
        self.max_sources = config.max_sources_per_window
        self.emit_empty = emit_empty
        self.late_dropped = 0
        self._open = {}  # window index -> WindowAccumulator
        self._closed_upto = None  # every window index below this is finalized
        self._next_empty = None  # first window index not yet emitted (emit_empty only)
        self._watermark = -math.inf

    def add(self, packet):
        """Accept one packet; return the windows this finalizes (usually none)."""
        if not math.isfinite(packet.ts):
            raise ValueError("Packet timestamp must be finite")
        index = math.floor(packet.ts / self.window_seconds)
        if self._closed_upto is not None and index < self._closed_upto:
            self.late_dropped += 1
            return []
        acc = self._open.get(index)
        if acc is None:
            acc = self._open[index] = WindowAccumulator(self.max_sources)
        acc.add(packet)
        return self.advance(packet.ts)

    def advance(self, now):
        """Move time forward without a packet; return windows now past their grace."""
        self._watermark = max(self._watermark, now)
        upto = math.floor((self._watermark - self.grace_seconds) / self.window_seconds)
        return self._close(upto)

    def flush(self):
        """Finalize every open window (end of input)."""
        return self._close(max(self._open) + 1 if self._open else None)

    def _close(self, upto):
        if upto is None or (self._closed_upto is not None and upto <= self._closed_upto):
            return []
        done = sorted(i for i in self._open if i < upto)
        if self.emit_empty and (done or self._next_empty is not None):
            indexes = range(self._next_empty if self._next_empty is not None else done[0], upto)
        else:
            indexes = done
        out = [self._record(i, self._open.pop(i, None)) for i in indexes]
        self._closed_upto = upto
        if self.emit_empty and out:
            self._next_empty = upto
        return out

    def _record(self, index, acc):
        acc = acc or WindowAccumulator()
        start = index * self.window_seconds
        return WindowRecord(
            window_start=start,
            window_end=start + self.window_seconds,
            vector=feature_vector(acc.features(self.window_seconds),
                                  feature_schema_version=FEATURE_SCHEMA_VERSION),
            packet_count=acc.n,
            capped=acc.capped,
            untracked_source_packets=acc.untracked_source_packets,
            source_counts=tuple(SourceCount(src, proto, count, acc.source_syns[src, proto])
                                for (src, proto), count in sorted(acc.source_protocols.items())),
        )


def aggregate_packets(packets, config=Config(), emit_empty=False):
    """Lazily yield WindowRecords for time-roughly-sorted packets (offline use)."""
    aggregator = WindowAggregator(config, emit_empty)
    for packet in packets:
        yield from aggregator.add(packet)
    yield from aggregator.flush()
