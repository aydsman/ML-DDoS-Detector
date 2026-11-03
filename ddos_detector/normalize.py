"""Shared raw-packet normalization for offline PCAP and live capture (IPv4 only)."""
import socket
import struct
from collections import Counter

from .features import Packet

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp"}

SKIP_REASONS = (
    "non_ip",
    "ipv6",
    "truncated_header",
    "bad_length",
    "unsupported_protocol",
    # link-layer / direction reasons, used by frames.py
    "vlan_tagged",
    "not_inbound",
    "broadcast",
    "multicast",
    "truncated_frame",
)


class SkipCounter(Counter):
    """Skipped-packet counts by reason; for logs and diagnostics only."""

    def record(self, reason):
        assert reason in SKIP_REASONS, reason
        self[reason] += 1


def normalize_ip_packet(ts, data, skips=None, ethertype=None):
    """Turn raw bytes starting at the IP header into a Packet, or None if skipped.

    Packet.size is the IPv4 Total Length field (IP header + transport header +
    payload); the Ethernet header is excluded and the captured byte count is
    never substituted. Pass ethertype when the link layer was already parsed.
    A non-first fragment counts for size and protocol but has no transport
    header. TCP flags are None (unknown), not 0, for a
    non-first fragment or when the TCP header was not captured; a real flags
    value of 0 stays 0. Non-TCP packets keep flags=0 unless they are non-first
    fragments, which are also None.
    """
    def skip(reason):
        if skips is not None:
            skips.record(reason)
        return None

    if ethertype is not None and ethertype != ETHERTYPE_IPV4:
        return skip("ipv6" if ethertype == ETHERTYPE_IPV6 else "non_ip")
    if not data:
        return skip("truncated_header")
    version = data[0] >> 4
    if version == 6:
        return skip("ipv6")
    if version != 4:
        return skip("non_ip")
    if len(data) < 20:
        return skip("truncated_header")

    ihl = (data[0] & 0x0F) * 4
    if ihl < 20:
        return skip("bad_length")
    if len(data) < ihl:
        return skip("truncated_header")
    total_length = struct.unpack("!H", data[2:4])[0]
    if total_length < ihl:
        return skip("bad_length")

    proto = PROTOCOLS.get(data[9])
    if proto is None:
        return skip("unsupported_protocol")

    frag_offset = struct.unpack("!H", data[6:8])[0] & 0x1FFF
    flags = 0
    if frag_offset > 0:
        flags = None
    elif proto == "tcp":
        flags = data[ihl + 13] if min(len(data), total_length) >= ihl + 14 else None
    return Packet(ts, socket.inet_ntoa(data[12:16]), proto, total_length, flags)
