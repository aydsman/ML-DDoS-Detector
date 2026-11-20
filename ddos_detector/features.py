"""Window feature extraction, used by both offline training and live capture."""
import math
from collections import Counter
from dataclasses import dataclass
from fractions import Fraction

from .config import FEATURE_NAMES

SYN = 0x02
ACK = 0x10


@dataclass(frozen=True)
class Packet:
    ts: float
    src: str
    proto: str  # "tcp", "udp" or "icmp"
    size: int  # IP packet length in bytes, including IP headers; excludes link-layer headers
    flags: int | None = 0  # TCP flags; 0 for non-TCP; None when unknown (e.g. non-first fragment)


def _entropy(counts):
    total = sum(counts)
    return -sum(c / total * math.log2(c / total) for c in counts) if total else 0.0


class WindowAccumulator:
    """Running counts for one window; the single home of the feature math.

    Memory is bounded by distinct sizes, protocols and tracked sources, not by
    packet count. With max_sources set, a source first seen after that many
    distinct sources is not tracked: its packets still count everywhere except
    the source features (unique_src_ips, src_ip_entropy), which then cover
    tracked sources only. Such packets are counted in untracked_source_packets.
    """

    def __init__(self, max_sources=None):
        self.max_sources = max_sources
        self.n = 0
        self.sizes = Counter()
        self.protos = Counter()
        self.srcs = Counter()
        self.source_protocols = Counter()
        self.source_syns = Counter()
        self.syn = self.synack = self.ack = 0
        self.untracked_source_packets = 0

    @property
    def capped(self):
        return self.untracked_source_packets > 0

    def add(self, p):
        self.n += 1
        self.sizes[p.size] += 1
        self.protos[p.proto] += 1
        if p.src in self.srcs or self.max_sources is None or len(self.srcs) < self.max_sources:
            self.srcs[p.src] += 1
            self.source_protocols[p.src, p.proto] += 1
            if p.proto == "tcp" and p.flags is not None and p.flags & SYN and not p.flags & ACK:
                self.source_syns[p.src, p.proto] += 1
        else:
            self.untracked_source_packets += 1
        # Packets with unknown flags (None) still count for size, protocol and source
        # features, but never as SYN, SYN-ACK or ACK evidence.
        if p.proto == "tcp" and p.flags is not None:
            if p.flags & SYN:
                if p.flags & ACK:
                    self.synack += 1
                else:
                    self.syn += 1
            if p.flags & ACK:
                self.ack += 1

    def _size_stats(self):
        """Byte sum and population standard deviation from the size histogram.

        Integer arithmetic over the histogram entries, so time and memory depend
        on distinct sizes, not packet count, and the variance is exact.
        """
        n = self.n
        total = sum(size * count for size, count in self.sizes.items())
        square_sum = sum(size * size * count for size, count in self.sizes.items())
        variance = Fraction(n * square_sum - total * total, n * n)
        return total, math.sqrt(variance)

    def features(self, window_seconds):
        n = self.n
        if n == 0:
            return {name: 0.0 for name in FEATURE_NAMES}
        size_sum, size_std = self._size_stats()
        return {
            "packet_rate": n / window_seconds,
            "byte_rate": size_sum / window_seconds,
            "syn_count": self.syn,
            "syn_ack_ratio": self.syn / max(self.synack, 1),
            "syn_no_ack_share": self.syn / max(self.syn + self.ack, 1),
            "pkt_size_mean": size_sum / n,
            "pkt_size_std": size_std,
            "unique_src_ips": len(self.srcs),
            "src_ip_entropy": _entropy(self.srcs.values()),
            "tcp_share": self.protos["tcp"] / n,
            "udp_share": self.protos["udp"] / n,
            "icmp_share": self.protos["icmp"] / n,
        }


def extract_features(packets, window_seconds):
    """Summarize one aggregate window of normalized inbound packets.

    Packet.size must use declared IP packet bytes for offline/live parity.
    Size standard deviation is the population statistic, in bytes.
    Capture filtering and raw-packet normalization belong to the adapters.
    """
    acc = WindowAccumulator()
    for p in packets:
        acc.add(p)
    return acc.features(window_seconds)


def window_start(ts, window_seconds):
    """Epoch-aligned window start: floor(ts / window_seconds) * window_seconds."""
    return math.floor(ts / window_seconds) * window_seconds


def windows(packets, window_seconds):
    """Group time-sorted packets into epoch-aligned, non-overlapping windows.

    Windows include their start and exclude their end. Windows between the
    first and last packet with no packets are yielded empty.
    """
    if not packets:
        return
    index = math.floor(packets[0].ts / window_seconds)
    bucket = []
    for p in packets:
        target = math.floor(p.ts / window_seconds)
        while target > index:
            yield index * window_seconds, bucket
            index += 1
            bucket = []
        bucket.append(p)
    yield index * window_seconds, bucket
