"""Rebuild tiny synthetic Ethernet PCAP fixtures; no sockets or production imports.

python -m tools.create_week2_fixtures --output /tmp/week2-fixtures
Expected feature values are reviewed literals in tests/fixtures/week2/expected.json;
this generator neither calculates nor updates them.
"""
import argparse
import hashlib
from pathlib import Path
import struct


VICTIM = "10.10.10.10"
A, B, C = "10.10.10.30", "10.10.10.31", "10.10.10.32"


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def address(ip):
    return bytes(int(octet) for octet in ip.split("."))


def transport(proto, length, src, dst, flags=0):
    if proto == 6:
        body = struct.pack("!HHIIHHHH", 40000, 80, 1, 0, (5 << 12) | flags, 8192, 0, 0)
        body += b"x" * (length - 20)
        pseudo = address(src) + address(dst) + struct.pack("!BBH", 0, 6, length)
        return body[:16] + struct.pack("!H", checksum(pseudo + body)) + body[18:]
    if proto == 17:
        # A zero UDP checksum is permitted in IPv4.
        return struct.pack("!HHHH", 40000, 80, length, 0) + b"u" * (length - 8)
    if proto == 1:
        body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"i" * (length - 8)
        return body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    raise ValueError("Fixture transport must be TCP, UDP or ICMP")


def ipv4(size, proto=6, src=A, dst=VICTIM, flags=0, fragment=0, ident=1, body=None):
    payload = transport(proto, size - 20, src, dst, flags) if body is None else body
    if len(payload) != size - 20:
        raise ValueError("Fixture payload length does not match declared IP length")
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, size, ident, fragment,
                         64, proto, 0, address(src), address(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ethernet(payload, ethertype=0x0800, pad=True):
    frame = bytes.fromhex("020000000010020000000030") + struct.pack("!H", ethertype) + payload
    return frame.ljust(60, b"\0") if pad else frame


def arp():
    return ethernet(struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1,
                                bytes.fromhex("020000000030"), address(A), bytes(6), address(VICTIM)),
                    ethertype=0x0806)


def pcap(records):
    """Record timestamps use literal integer seconds/microseconds, without rounding."""
    result = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for seconds, micros, frame, original_length in records:
        result += struct.pack("<IIII", seconds, micros, len(frame), original_length or len(frame))
        result += frame
    return bytes(result)


def fixture_bytes():
    mixed = [
        (100, 100000, ethernet(ipv4(60, src=A, flags=0x02)), None),
        (100, 200000, ethernet(ipv4(100, src=B, flags=0x12)), None),
        (100, 300000, ethernet(ipv4(80, proto=17, src=A)), None),
        (100, 400000, ethernet(ipv4(200, src=VICTIM, dst=A, flags=0x12)), None),
        (100, 600000, arp(), None),
        (100, 999999, ethernet(ipv4(80, proto=1, src=B)), None),
        (101, 0, ethernet(ipv4(60, src=A, flags=0x02)), None),
        (101, 250000, ethernet(ipv4(60, src=A, flags=0x04)), None),
        (101, 500000, ethernet(ipv4(60, proto=17, src=B)), None),
        (101, 750000, ethernet(ipv4(60, proto=17, src=C)), None),
        (101, 900000, ethernet(ipv4(40, src=A, dst="10.10.10.99", flags=0x02)), None),
        (103, 0, ethernet(ipv4(28, proto=1, src=A)), None),
    ]
    # Two fragments form one synthetic 60-byte TCP segment. Feature extraction
    # counts IP packets separately and does not reassemble their transport data.
    segment = transport(6, 60, A, VICTIM, flags=0x02)
    truncated = ethernet(ipv4(100, src=B, flags=0x12), pad=False)
    malformed = bytearray(ipv4(40))
    malformed[2:4] = struct.pack("!H", 10)  # deliberately shorter than the IP header
    malformed[10:12] = b"\0\0"
    malformed[10:12] = struct.pack("!H", checksum(bytes(malformed[:20])))
    ipv6 = struct.pack("!IHBB16s16s", 6 << 28, 0, 59, 64, bytes(15) + b"\x01", bytes(15) + b"\x02")
    fragments = [
        (200, 100000, ethernet(ipv4(60, fragment=0x2000, ident=42, body=segment[:40])), None),
        (200, 200000, ethernet(ipv4(40, fragment=5, ident=42, body=segment[40:])), None),
        (200, 300000, truncated[:44], len(truncated)),  # Ethernet + IP + 10 captured TCP bytes
        (200, 400000, ethernet(ipv4(40, proto=17, src=B)), None),
        (200, 500000, ethernet(bytes(malformed)), None),
        (200, 600000, ethernet(ipv6, ethertype=0x86dd), None),
    ]
    return {"synthetic-mixed-boundaries.pcap": pcap(mixed),
            "synthetic-fragments-truncation.pcap": pcap(fragments)}


def write_fixtures(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    blobs = fixture_bytes()
    for name in blobs:
        if (directory / name).exists():
            raise FileExistsError(f"Refusing to overwrite {directory / name}")
    for name, content in blobs.items():
        (directory / name).write_bytes(content)
    return {name: hashlib.sha256(content).hexdigest() for name, content in blobs.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", required=True, help="new output directory; existing files are not overwritten")
    args = parser.parse_args(argv)
    for name, digest in write_fixtures(args.output).items():
        print(f"{digest}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
