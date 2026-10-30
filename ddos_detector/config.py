"""Shared settings for offline training and live capture."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    window_seconds: float = 1.0
    data_dir: str = "data"
    victim_ip: str = "10.10.10.10"  # inbound traffic is traffic addressed to this host


FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "syn_count",
    "syn_ack_ratio",
    "syn_no_ack_share",
    "pkt_size_mean",
    "pkt_size_std",
    "unique_src_ips",
    "src_ip_entropy",
    "tcp_share",
    "udp_share",
    "icmp_share",
]
