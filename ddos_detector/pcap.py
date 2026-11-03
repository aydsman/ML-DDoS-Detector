"""Lazy reader for classic libpcap files (Ethernet linktype only)."""
import struct

LINKTYPE_ETHERNET = 1
MAX_RECORD_BYTES = 1 << 24  # sanity cap so a corrupt length cannot trigger a huge read

# magic as read in the file's own byte order -> (struct endian prefix, timestamp divisor)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapError(ValueError):
    """The file is not a readable classic Ethernet pcap."""


def read_pcap(path):
    """Yield (timestamp_seconds, frame_bytes) for each record, one at a time.

    Raises PcapError on a bad header, a non-Ethernet linktype, pcapng input or a
    damaged record; records before the damage have already been yielded.
    """
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise PcapError(f"{path}: file too short for a pcap header")
        if header[:4] == _PCAPNG_MAGIC:
            raise PcapError(f"{path}: pcapng is not supported; convert it first "
                            "(e.g. editcap -F pcap in.pcapng out.pcap)")
        if header[:4] not in _MAGICS:
            raise PcapError(f"{path}: not a pcap file (bad magic {header[:4].hex()})")
        endian, divisor = _MAGICS[header[:4]]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise PcapError(f"{path}: linktype {linktype} is not Ethernet (1)")

        index = 0
        while True:
            rec = f.read(16)
            if not rec:
                return
            if len(rec) < 16:
                raise PcapError(f"{path}: truncated record header after {index} records")
            sec, frac, incl_len, orig_len = struct.unpack(endian + "IIII", rec)
            if incl_len > orig_len or incl_len > MAX_RECORD_BYTES:
                raise PcapError(f"{path}: record {index} has bad length "
                                f"(captured {incl_len}, original {orig_len})")
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                raise PcapError(f"{path}: record {index} truncated "
                                f"({len(frame)} of {incl_len} bytes)")
            yield sec + frac / divisor, frame
            index += 1
