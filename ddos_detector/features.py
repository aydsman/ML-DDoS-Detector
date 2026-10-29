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
    size: int  # IP packet length in bytes, including IP headers; excludes link-layer headers
    flags: int | None = 0  # TCP flags; 0 for non-TCP; None when unknown (e.g. non-first fragment)


def _entropy(counts):
    total = sum(counts)
    return -sum(c / total * math.log2(c / total) for c in counts) if total else 0.0


def extract_features(packets, window_seconds):
    """Summarize one aggregate window of normalized inbound packets.

    Packet.size must use declared IP packet bytes for offline/live parity.
    Size standard deviation is the population statistic, in bytes.
    Capture filtering and raw-packet normalization belong to the adapters.
    """
    n = len(packets)
    if n == 0:
        return {name: 0.0 for name in FEATURE_NAMES}

    sizes = [p.size for p in packets]
    # Packets with unknown flags (None) still count for size, protocol and source
    # features, but never as SYN, SYN-ACK or ACK evidence.
    tcp = [p for p in packets if p.proto == "tcp" and p.flags is not None]
    syn = sum(1 for p in tcp if p.flags & SYN and not p.flags & ACK)
    synack = sum(1 for p in tcp if p.flags & SYN and p.flags & ACK)
    ack = sum(1 for p in tcp if p.flags & ACK)
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
