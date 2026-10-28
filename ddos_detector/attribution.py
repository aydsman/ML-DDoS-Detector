"""Stage 2 source attribution: deterministic rules that run after an aggregate alert.

The model scores a whole window and never names an IP. This module only decides,
from per-(source IP, protocol) packet counts, which source is a block candidate
and whether a block may be requested. It sends no firewall request itself: a
"block_requested" decision is not an active block until a firewall adapter
confirms it.
"""
import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from typing import Mapping

from .features import ACK, SYN, Packet

PROTOCOLS = ("tcp", "udp", "icmp")
MONITOR_ONLY = "monitor_only"
AUTOMATIC = "automatic"
SHARE_BASIS = "all_selected_packets"


@dataclass(frozen=True)
class PolicyConfig:
    """Policy settings. Thresholds have no defaults: they come from lab/validation data."""

    packet_rate_thresholds: Mapping[str, float]  # packets/s per protocol; exceeded when rate > value
    min_share: float  # minimum fraction of all selected inbound packets; met when share >= value
    syn_rate_threshold: float | None = None  # TCP SYN-only packets/s; exceeded when rate > value
    window_seconds: float = 1.0
    required_windows: int = 3
    block_seconds: float = 300.0
    max_active_blocks: int = 20  # provisional lab cap, configurable
    protected_ip: str = "10.10.10.10"
    allowlist: frozenset = frozenset()
    allowlist_verified: bool = False  # automatic mode requests nothing until this is true
    mode: str = MONITOR_ONLY

    def __post_init__(self):
        if self.mode not in (MONITOR_ONLY, AUTOMATIC):
            raise ValueError("mode must be monitor_only or automatic")
        if self.window_seconds <= 0 or self.block_seconds <= 0:
            raise ValueError("window_seconds and block_seconds must be positive")
        if self.required_windows < 1 or self.max_active_blocks < 1:
            raise ValueError("required_windows and max_active_blocks must be at least 1")
        if not 0 <= self.min_share <= 1:
            raise ValueError("min_share must be between zero and one")
        unknown = set(self.packet_rate_thresholds) - set(PROTOCOLS)
        if unknown:
            raise ValueError(f"unknown protocols in packet_rate_thresholds: {sorted(unknown)}")
        ipaddress.IPv4Address(self.protected_ip)
        for address in self.allowlist:
            ipaddress.IPv4Address(address)


@dataclass(frozen=True)
class GroupCount:
    packets: int
    syn_packets: int = 0  # TCP SYN-only packets whose flags are known


@dataclass(frozen=True)
class WindowObservation:
    window_start: float  # epoch seconds
    available: bool  # False for a capture failure; never treated as zero traffic
    aggregate_attack: bool
    total_packets: int  # all selected inbound packets: the share denominator
    groups: Mapping[tuple, GroupCount] = field(default_factory=dict)  # (src_ip, protocol) -> counts


@dataclass(frozen=True)
class SourceDecision:
    src_ip: str
    protocol: str
    decision: str  # no_action, alert or block_requested
    reason: str
    packets_per_second: float
    syn_per_second: float | None  # None for UDP and ICMP
    packet_share: float
    consecutive_windows: int
    share_basis: str = SHARE_BASIS


def group_packets(window_start, packets, aggregate_attack, available=True):
    """Build a WindowObservation from normalized Packet records of one window."""
    counts = Counter((p.src, p.proto) for p in packets)
    syns = Counter(
        (p.src, p.proto)
        for p in packets
        if p.proto == "tcp" and p.flags is not None and p.flags & SYN and not p.flags & ACK
    )
    groups = {key: GroupCount(n, syns[key]) for key, n in counts.items()}
    return WindowObservation(window_start, available, aggregate_attack, len(packets), groups)


class SourcePolicy:
    """Tracks streaks and requested blocks across consecutive windows, in time order."""

    def __init__(self, config):
        self.config = config
        self._streaks = {}
        self._blocks = {}  # src_ip -> expires_at, from the first block request

    @property
    def active_blocks(self):
        return dict(self._blocks)

    def _never_block(self, src_ip):
        cfg = self.config
        address = ipaddress.IPv4Address(src_ip)
        return address.is_loopback or src_ip == cfg.protected_ip or src_ip in cfg.allowlist

    def _qualifies(self, protocol, group, total, ws):
        cfg = self.config
        rate = group.packets / ws
        syn_rate = group.syn_packets / ws if protocol == "tcp" else None
        share = group.packets / total if total else 0.0
        threshold = cfg.packet_rate_thresholds.get(protocol)
        over_rate = threshold is not None and rate > threshold
        over_syn = syn_rate is not None and cfg.syn_rate_threshold is not None and syn_rate > cfg.syn_rate_threshold
        return (over_rate or over_syn) and share >= cfg.min_share, rate, syn_rate, share

    def evaluate(self, window):
        """Return decisions for one window; windows must arrive in time order."""
        cfg = self.config
        for ip in [ip for ip, expires in self._blocks.items() if window.window_start >= expires]:
            del self._blocks[ip]

        # Unavailable, benign and measured-empty windows break every streak.
        if not window.available or not window.aggregate_attack or window.total_packets <= 0:
            self._streaks = {}
            return []

        streaks = {}
        decisions = []
        ordered = sorted(window.groups.items(), key=lambda item: (-item[1].packets, item[0]))
        for (src_ip, protocol), group in ordered:
            ok, rate, syn_rate, share = self._qualifies(protocol, group, window.total_packets, cfg.window_seconds)
            if not ok:
                continue
            if self._never_block(src_ip):
                decisions.append(SourceDecision(src_ip, protocol, "no_action", "never_block", rate, syn_rate, share, 0))
                continue
            streak = self._streaks.get((src_ip, protocol), 0) + 1
            streaks[(src_ip, protocol)] = streak
            decision, reason = self._decide(src_ip, streak, window.window_start)
            decisions.append(SourceDecision(src_ip, protocol, decision, reason, rate, syn_rate, share, streak))
        self._streaks = streaks
        return decisions

    def _decide(self, src_ip, streak, now):
        cfg = self.config
        if streak < cfg.required_windows:
            return "no_action", "streak_below_required"
        if cfg.mode == MONITOR_ONLY:
            return "alert", "monitor_only"
        if not cfg.allowlist_verified:
            return "alert", "allowlist_unverified"
        if src_ip in self._blocks:
            return "no_action", "already_blocked"
        if len(self._blocks) >= cfg.max_active_blocks:
            return "alert", "block_cap_reached"
        self._blocks[src_ip] = now + cfg.block_seconds
        return "block_requested", "policy_satisfied"
