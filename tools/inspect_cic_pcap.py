"""Read-only inspection of CIC-DDoS2019 PCAP pieces (stdlib only).

For each named piece it records identity (full path, size, member SHA-256),
timestamps (raw epoch and UTC interpretation, no timezone shift is applied),
packet/protocol mix, TCP flag mix, top source/destination addresses and a
per-second packet-rate summary.  Nothing is written next to the input and
nothing is extracted; raw captures stay outside Git.

    python -m tools.inspect_cic_pcap PIECE [PIECE ...] [--victim IP]
        [--max-packets N] [--no-hash] [--out report.json]

--max-packets limits how many packets are read from the START of each piece;
the report records the limit and whether it truncated the scan, so a sampled
result is never presented as a full-piece result.
"""
import argparse
import datetime
import hashlib
import json
import os
import struct
import sys
from collections import Counter

TOOL_VERSION = "1"
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PROTOS = {1: "icmp", 6: "tcp", 17: "udp"}
TOP_N = 5


def sha256_file(path, chunk=1 << 22):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                return digest.hexdigest().upper()
            digest.update(block)


def utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def flag_class(flags):
    syn, ack, rst, fin = flags & 2, flags & 16, flags & 4, flags & 1
    if rst:
        return "rst"
    if syn and ack:
        return "synack"
    if syn:
        return "syn"
    if fin:
        return "fin"
    if ack:
        return "ack"
    return "other"


def inspect_piece(path, victim, max_packets, do_hash):
    report = {
        "path": os.path.abspath(path),
        "member_name": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "sha256": sha256_file(path) if do_hash else None,
        "victim_filter": victim,
        "max_packets": max_packets,
    }
    per_second = Counter()
    proto = Counter()
    flags = Counter()
    src_all = Counter()
    dst_all = Counter()
    src_to_victim = Counter()
    ports_udp = Counter()
    non_ipv4 = 0
    malformed_ipv4 = 0
    non_first_fragments = 0
    truncated_pkt = 0
    total = 0
    first = last = None
    with open(path, "rb") as handle:
        header = handle.read(24)
        magic = header[:4]
        if magic not in MAGICS:
            raise ValueError(f"{path}: not a classic pcap (magic {magic.hex()})")
        endian, resolution = MAGICS[magic]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        report["pcap"] = {"magic": magic.hex(), "linktype": linktype,
                          "timestamp_resolution_s": resolution}
        rec = struct.Struct(endian + "IIII")
        while max_packets is None or total < max_packets:
            raw = handle.read(16)
            if not raw:
                break
            if len(raw) < 16:
                truncated_pkt += 1  # partial record header: incomplete input, not clean EOF
                break
            sec, frac, incl, orig = rec.unpack(raw)
            data = handle.read(incl)
            if len(data) < incl:
                truncated_pkt += 1
                break
            ts = sec + frac * resolution
            total += 1
            if first is None:
                first = ts
            last = ts
            per_second[int(ts)] += 1
            if linktype != 1 or len(data) < 34 or data[12:14] != b"\x08\x00":
                non_ipv4 += 1
                continue
            ihl = (data[14] & 0x0F) * 4
            total_length = struct.unpack(">H", data[16:18])[0]
            # Scope rule: a usable IPv4 packet has version 4, a real header that was
            # captured, and a Total Length covering that header.  Anything else is
            # counted separately and never contributes to the parsed statistics.
            if (data[14] >> 4 != 4 or ihl < 20 or len(data) < 14 + ihl
                    or total_length < ihl):
                malformed_ipv4 += 1
                continue
            fragment_offset = struct.unpack(">H", data[20:22])[0] & 0x1FFF
            p = data[23]
            src = ".".join(map(str, data[26:30]))
            dst = ".".join(map(str, data[30:34]))
            proto[PROTOS.get(p, f"ip{p}")] += 1
            src_all[src] += 1
            dst_all[dst] += 1
            to_victim = victim is None or dst == victim
            if to_victim:
                src_to_victim[src] += 1
            if fragment_offset:
                # A non-first fragment carries payload continuation, not a transport
                # header, so its bytes must not be read as TCP flags or UDP ports.
                non_first_fragments += 1
                continue
            if p == 6 and to_victim and len(data) >= 14 + ihl + 14:
                flags[flag_class(data[14 + ihl + 13])] += 1
            if p == 17 and to_victim and len(data) >= 14 + ihl + 4:
                ports_udp[struct.unpack(">H", data[14 + ihl + 2:14 + ihl + 4])[0]] += 1
        at_eof = not truncated_pkt and not handle.read(1)
    rates = sorted(per_second.values())
    report["scan"] = {
        "packets_read": total,
        "reached_end_of_file": at_eof,
        "truncated_final_record": bool(truncated_pkt),
        "non_ipv4_or_unparsed": non_ipv4,
        "malformed_ipv4_excluded": malformed_ipv4,
        "non_first_fragments_no_transport_parse": non_first_fragments,
    }
    if total:
        report["time"] = {
            "first_epoch": first, "last_epoch": last,
            "first_utc": utc(first), "last_utc": utc(last),
            "timezone_note": "raw pcap epoch interpreted as UTC; no offset applied",
            "span_s": round(last - first, 6),
        }
        report["rate_per_second"] = {
            "seconds_with_traffic": len(rates),
            "min": rates[0], "median": rates[len(rates) // 2], "max": rates[-1],
        }
    report["ipv4_protocols"] = dict(proto)
    report["top_sources_all"] = src_all.most_common(TOP_N)
    report["top_destinations_all"] = dst_all.most_common(TOP_N)
    report["top_sources_to_victim"] = src_to_victim.most_common(TOP_N)
    report["tcp_flag_classes_to_victim"] = dict(flags)
    report["udp_top_dst_ports_to_victim"] = ports_udp.most_common(TOP_N)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pieces", nargs="+")
    ap.add_argument("--victim", help="only count packets whose IPv4 dst equals this")
    ap.add_argument("--max-packets", type=int, default=None)
    ap.add_argument("--no-hash", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    result = {
        "tool": "tools/inspect_cic_pcap.py", "tool_version": TOOL_VERSION,
        "python": sys.version.split()[0],
        "run_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "pieces": [inspect_piece(p, args.victim, args.max_packets, not args.no_hash)
                   for p in args.pieces],
    }
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        if os.path.exists(args.out):
            sys.exit(f"refusing to overwrite {args.out}")
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
