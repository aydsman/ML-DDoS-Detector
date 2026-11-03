"""Check per-window features against an independent tshark (or scapy) computation.

The feature formulas below are re-implemented from docs/feature-contract.md and
docs/design.md on purpose: nothing from ddos_detector.features is imported, so
this agrees with the package only if both read the contract the same way.

    python -m tools.verify_pcap_features data\\lab-runs\\pr16-syn-run1\\syn1.pcap
"""
import argparse
import math
import os
import subprocess
import sys
from collections import Counter
from decimal import Decimal

from ddos_detector.config import FEATURE_NAMES, Config
from ddos_detector.offline import extract_pcap

DEFAULT_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
PROTOS = {"1": "icmp", "6": "tcp", "17": "udp"}
REL_TOL = 1e-9


def find_tshark(explicit=None):
    for path in (explicit, os.environ.get("TSHARK"), DEFAULT_TSHARK):
        if path and os.path.exists(path):
            return path
    return None


def tshark_rows(pcap, victim, tshark):
    """Inbound IPv4 rows (ts Decimal, src, proto, ip.len, tcp flags or None)."""
    cmd = [tshark, "-r", pcap, "-Y", f"ip.dst=={victim}", "-T", "fields",
           "-E", "occurrence=f", "-E", "separator=/t",
           "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
           "-e", "ip.len", "-e", "tcp.flags"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = []
    for line in out.splitlines():
        ts, src, dst, proto, length, flags = (line.split("\t") + [""] * 6)[:6]
        # The display filter also matches the quoted inner header of ICMP errors,
        # so re-check the outer destination (first occurrence) here.
        proto = PROTOS.get(proto)
        if proto is None or dst != victim:
            continue
        known = proto == "tcp" and flags != ""
        rows.append((Decimal(ts), src, proto, int(length), int(flags, 16) if known else
                     (None if proto == "tcp" else 0)))
    return rows


def scapy_rows(pcap, victim):
    from scapy.all import IP, TCP, rdpcap

    rows = []
    for p in rdpcap(pcap):
        if IP not in p or p[IP].dst != victim:
            continue
        ip = p[IP]
        proto = PROTOS.get(str(ip.proto))
        if proto is None:
            continue
        if proto != "tcp":
            flags = 0
        elif ip.frag > 0 or TCP not in p:
            flags = None
        else:
            flags = int(p[TCP].flags)
        rows.append((Decimal(p.time), ip.src, proto, ip.len, flags))
    return rows


def window_features(rows, ws):
    """The 12 features for one window's rows, straight from the contract text."""
    n = len(rows)
    sizes = [r[3] for r in rows]
    known = [r[4] for r in rows if r[2] == "tcp" and r[4] is not None]
    syn = sum(1 for f in known if f & 0x02 and not f & 0x10)
    synack = sum(1 for f in known if f & 0x02 and f & 0x10)
    ack = sum(1 for f in known if f & 0x10)
    mean = sum(sizes) / n
    srcs = Counter(r[1] for r in rows)
    entropy = 0.0
    for c in srcs.values():
        entropy -= (c / n) * math.log2(c / n)
    share = lambda proto: sum(1 for r in rows if r[2] == proto) / n
    return {
        "packet_rate": n / ws,
        "byte_rate": sum(sizes) / ws,
        "syn_count": syn,
        "syn_ack_ratio": syn / max(synack, 1),
        "syn_no_ack_share": syn / max(syn + ack, 1),
        "pkt_size_mean": mean,
        "pkt_size_std": math.sqrt(sum((s - mean) ** 2 for s in sizes) / n),
        "unique_src_ips": len(srcs),
        "src_ip_entropy": entropy,
        "tcp_share": share("tcp"),
        "udp_share": share("udp"),
        "icmp_share": share("icmp"),
    }


def reference_windows(rows, ws):
    """Epoch-aligned windows (start-inclusive) from exact decimal timestamps."""
    buckets = {}
    dws = Decimal(str(ws))
    for row in rows:
        buckets.setdefault(math.floor(row[0] / dws), []).append(row)
    return {float(i * dws): window_features(b, ws) for i, b in sorted(buckets.items())}


def compare(pcap, rows, config=None):
    """Return a result dict comparing the package's records with the reference rows."""
    config = config or Config()
    records, _ = extract_pcap(pcap, config)
    ours = {r.window_start: r for r in records}
    theirs = reference_windows(rows, config.window_seconds)
    result = {"windows": len(theirs), "packets": len(rows),
              "problems": [], "max_abs": dict.fromkeys(FEATURE_NAMES, 0.0),
              "max_rel": dict.fromkeys(FEATURE_NAMES, 0.0)}
    if sum(r.packet_count for r in records) != len(rows):
        result["problems"].append(
            f"packet count {sum(r.packet_count for r in records)} != {len(rows)}")
    if set(ours) != set(theirs):
        result["problems"].append(f"window starts differ: only ours "
                                  f"{sorted(set(ours) - set(theirs))}, only reference "
                                  f"{sorted(set(theirs) - set(ours))}")
    for start in sorted(set(ours) & set(theirs)):
        mine = ours[start].features
        for name in FEATURE_NAMES:
            want, got = theirs[start][name], mine[name]
            diff = abs(got - want)
            rel = diff / abs(want) if want else diff
            result["max_abs"][name] = max(result["max_abs"][name], diff)
            result["max_rel"][name] = max(result["max_rel"][name], rel)
            if not math.isclose(got, want, rel_tol=REL_TOL, abs_tol=1e-12):
                result["problems"].append(f"window {start} {name}: ours {got!r} reference {want!r}")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("pcaps", nargs="+")
    parser.add_argument("--engine", choices=["tshark", "scapy"], default="tshark")
    parser.add_argument("--tshark", help="path to tshark.exe (or set TSHARK)")
    parser.add_argument("--victim", default=Config.victim_ip)
    parser.add_argument("--window", type=float, default=Config.window_seconds)
    args = parser.parse_args(argv)

    from dataclasses import replace
    config = replace(Config(), victim_ip=args.victim, window_seconds=args.window)
    tshark = find_tshark(args.tshark)
    if args.engine == "tshark" and tshark is None:
        print("error: tshark not found; pass --tshark or set TSHARK", file=sys.stderr)
        return 2
    failed = False
    print(f"{'pcap':40} {'windows':>7} {'packets':>7} {'max_abs':>10} {'max_rel':>10}  result")
    for pcap in args.pcaps:
        rows = (tshark_rows(pcap, args.victim, tshark) if args.engine == "tshark"
                else scapy_rows(pcap, args.victim))
        result = compare(pcap, rows, config)
        ok = not result["problems"]
        failed |= not ok
        print(f"{os.path.basename(pcap):40} {result['windows']:7} {result['packets']:7} "
              f"{max(result['max_abs'].values()):10.2e} {max(result['max_rel'].values()):10.2e}  "
              f"{'OK' if ok else 'MISMATCH'}")
        for problem in result["problems"][:20]:
            print("   ", problem)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
