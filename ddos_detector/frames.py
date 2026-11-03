"""Ethernet frame parsing: raw frame -> inbound IPv4 Packet or a counted skip reason."""
import struct
from dataclasses import dataclass

from .config import Config
from .features import Packet
from .normalize import ETHERTYPE_IPV4, ETHERTYPE_IPV6, SkipCounter, normalize_ip_packet
from .pcap import read_pcap

ETH_HEADER_LEN = 14
VLAN_ETHERTYPES = (0x8100, 0x88A8)
BROADCAST_IP = b"\xff\xff\xff\xff"


@dataclass(frozen=True)
class FrameResult:
    packet: Packet | None
    skip: str | None = None  # a normalize.SKIP_REASONS entry when packet is None


def frame_to_packet(frame, ts, victim_ip=Config.victim_ip, skips=None):
    """Parse one Ethernet II frame; keep it only if it is IPv4 addressed to victim_ip.

    Size and flags rules are normalize_ip_packet's; Ethernet padding past the
    IPv4 Total Length is ignored. VLAN-tagged frames are skipped, not unwrapped.
    """
    def skip(reason):
        if skips is not None:
            skips.record(reason)
        return FrameResult(None, reason)

    if len(frame) < ETH_HEADER_LEN:
        return skip("truncated_frame")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype in VLAN_ETHERTYPES:
        return skip("vlan_tagged")
    if ethertype != ETHERTYPE_IPV4:
        return skip("ipv6" if ethertype == ETHERTYPE_IPV6 else "non_ip")

    ip = frame[ETH_HEADER_LEN:]
    if len(ip) >= 20 and ip[0] >> 4 == 4:
        dst = ip[16:20]
        if dst == BROADCAST_IP:
            return skip("broadcast")
        if 224 <= dst[0] <= 239:
            return skip("multicast")
        if ".".join(map(str, dst)) != victim_ip:
            return skip("not_inbound")

    local = SkipCounter()
    packet = normalize_ip_packet(ts, ip, local, ethertype=ETHERTYPE_IPV4)
    if packet is None:
        return skip(next(iter(local)))
    return FrameResult(packet)


def iter_packets(path, victim_ip=Config.victim_ip, skips=None):
    """Lazily yield inbound Packets from a pcap; skip reasons go into skips (a SkipCounter)."""
    for ts, frame in read_pcap(path):
        packet = frame_to_packet(frame, ts, victim_ip, skips).packet
        if packet is not None:
            yield packet
