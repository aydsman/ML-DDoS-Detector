"""Per-source, per-protocol one-second window summary of lab server captures.

Read-only. Uses the repository's own iter_packets (inbound IPv4 TCP/UDP/ICMP to the
protected host) and one-second epoch windows. The first and last window of each
capture hold part of a neighbouring interval and are dropped. Each group's own first and last window are additionally dropped in the trim_* fields.

Usage: python -m tools.lab_window_summary CAPTURE.pcap [...] [--json out.json]
"""
import argparse
import json
import statistics
from collections import defaultdict

from ddos_detector.frames import iter_packets
from ddos_detector.normalize import SkipCounter

SYN, ACK = 0x02, 0x10


def summarize(path):
    wins = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # window -> (src, proto) -> [pkts, syn_only]
    skips = SkipCounter()
    for p in iter_packets(path, skips=skips):
        g = wins[int(p.ts)][(p.src, p.proto)]
        g[0] += 1
        if p.proto == "tcp" and p.flags is not None and p.flags & SYN and not p.flags & ACK:
            g[1] += 1
    keys = sorted(wins)
    inner = keys[1:-1] if len(keys) > 2 else []
    per = defaultdict(lambda: {"pps": [], "syn": [], "share": [], "win": []})
    total = []
    for w in inner:
        all_pk = sum(v[0] for v in wins[w].values())
        total.append(all_pk)
        for (src, proto), (n, syn) in wins[w].items():
            d = per[f"{src}/{proto}"]
            d["pps"].append(n)
            d["syn"].append(syn)
            d["share"].append(n / all_pk)
            d["win"].append(w)
    out = {"windows_used": len(inner), "windows_dropped_edges": len(keys) - len(inner),
           "total_pps": {"median": statistics.median(total) if total else None, "max": max(total, default=None)},
           "skipped": dict(getattr(skips, "counts", {}) or {}), "groups": {}}
    for g, d in sorted(per.items()):
        out["groups"][g] = {"windows": len(d["pps"]), "pps_min": min(d["pps"]), "pps_median": statistics.median(d["pps"]),
                            "pps_max": max(d["pps"]), "syn_only_min": min(d["syn"]), "syn_only_max": max(d["syn"]),
                            "share_min": round(min(d["share"]), 3), "share_max": round(max(d["share"]), 3)}
        # A group that starts or stops inside the capture has partial first/last windows: also report it trimmed.
        if len(d["pps"]) > 2:
            t = slice(1, -1)
            out["groups"][g].update({"trim_windows": len(d["pps"]) - 2, "trim_pps_min": min(d["pps"][t]),
                                     "trim_pps_median": statistics.median(d["pps"][t]), "trim_pps_max": max(d["pps"][t]),
                                     "trim_syn_only_min": min(d["syn"][t]), "trim_syn_only_max": max(d["syn"][t]),
                                     "trim_share_min": round(min(d["share"][t]), 3), "trim_share_max": round(max(d["share"][t]), 3)})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--json")
    args = ap.parse_args()
    result = {path: summarize(path) for path in args.captures}
    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=1)
    for path, r in result.items():
        print(path, "windows", r["windows_used"], "total pps", r["total_pps"])
        for g, v in r["groups"].items():
            print("  ", g, v)


if __name__ == "__main__":
    main()
