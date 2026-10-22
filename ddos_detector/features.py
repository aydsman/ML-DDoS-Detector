"""Window feature extraction, used by both offline training and live capture."""
import math
from collections import Counter
from dataclasses import dataclass
from statistics import mean, pstdev

from .config import FEATURE_NAMES

SYN = 0x02
ACK = 0x10


@dataclass(frozen=True)
class Packet:
    ts: float
    src: str
    proto: str  # "tcp", "udp" or "icmp"
    size: int
    flags: int = 0  # TCP flags, 0 for non-TCP


def _entropy(counts):
    total = sum(counts)
    return -sum(c / total * math.log2(c / total) for c in counts) if total else 0.0


def extract_features(packets, window_seconds):
    """Return a dict keyed by FEATURE_NAMES for one window of packets."""
    n = len(packets)
    if n == 0:
        return {name: 0.0 for name in FEATURE_NAMES}

    sizes = [p.size for p in packets]
    syn = sum(1 for p in packets if p.proto == "tcp" and p.flags & SYN and not p.flags & ACK)
    synack = sum(1 for p in packets if p.proto == "tcp" and p.flags & SYN and p.flags & ACK)
    ack = sum(1 for p in packets if p.proto == "tcp" and p.flags & ACK)
    protos = Counter(p.proto for p in packets)
    srcs = Counter(p.src for p in packets)

    return {
        "packet_rate": n / window_seconds,
        "byte_rate": sum(sizes) / window_seconds,
        "syn_count": syn,
        "syn_ack_ratio": syn / max(synack, 1),
        "syn_no_ack_share": syn / max(syn + ack, 1),
        "pkt_size_mean": mean(sizes),
        "pkt_size_std": pstdev(sizes),
        "unique_src_ips": len(srcs),
        "src_ip_entropy": _entropy(srcs.values()),
        "tcp_share": protos["tcp"] / n,
        "udp_share": protos["udp"] / n,
        "icmp_share": protos["icmp"] / n,
    }


def windows(packets, window_seconds):
    """Group time-sorted packets into non-overlapping windows."""
    if not packets:
        return
    start = packets[0].ts
    bucket = []
    for p in packets:
        while p.ts >= start + window_seconds:
            yield start, bucket
            start += window_seconds
            bucket = []
        bucket.append(p)
    yield start, bucket
