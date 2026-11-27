"""Measure each lab VM's clock against the host, with an error bound, for issue #49.

Run on the host before NAT is turned off and again after it is turned back on.
For every VM, one SSH session answers repeated `date` requests. Each answer is
bracketed by host timestamps taken just before the request and just after the
reply, so the VM clock was read somewhere inside that interval:

    offset = vm_time - midpoint(host_before, host_after)
    bound  = (host_after - host_before) / 2      (the offset is within +/- bound)

The sample with the smallest round trip is kept. The export compares a before
and an after file to bound drift during the session; one file alone is not
enough evidence of clock agreement.

Usage (host, NAT on):
  python -m tools.lab_clock_check --out D:/lab-rerec/<session-id>/clock-before.json
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

VMS = {"server": 2222, "client": 2223, "attacker": 2224}
TOOL_VERSION = "lab-clock-1"
REMOTE_LOOP = 'while read -r _; do date +%s.%N; done'


def ssh_command(port, user="lab", host="127.0.0.1"):
    return ["ssh", "-o", "BatchMode=yes", "-p", str(port), f"{user}@{host}", REMOTE_LOOP]


def measure(command, samples=20, clock=time.time):
    """Run command (a remote 'read line, print epoch' loop) and return the tightest sample."""
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    rows = []
    try:
        for _ in range(samples + 1):  # the first answer includes session start-up; drop it
            before = clock()
            proc.stdin.write("\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            after = clock()
            if not line:
                raise RuntimeError(f"no answer from {' '.join(command)}: {proc.stderr.read().strip()}")
            rows.append((before, float(line), after))
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    rows = rows[1:]
    before, vm, after = min(rows, key=lambda row: row[2] - row[0])
    return {"offset_seconds": round(vm - (before + after) / 2, 6), "bound_seconds": round((after - before) / 2, 6),
            "samples": len(rows), "host_epoch": round((before + after) / 2, 6)}


def check(vms=VMS, samples=20, command_for=ssh_command):
    return {"tool": "tools/lab_clock_check.py", "tool_version": TOOL_VERSION, "measured_at_host_epoch": time.time(),
            "definition": "offset = vm_clock - host_clock; true offset within +/- bound",
            "vms": {name: {"port": port, **measure(command_for(port), samples)} for name, port in vms.items()}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, help="new JSON file (must not exist)")
    ap.add_argument("--samples", type=int, default=20)
    args = ap.parse_args(argv)
    result = check(samples=args.samples)
    with Path(args.out).open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result["vms"], indent=2))


if __name__ == "__main__":
    main()
