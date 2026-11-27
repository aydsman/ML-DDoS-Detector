"""Measure each lab VM's clock against the host, with an error bound, for issue #49.

Run on the host before NAT is turned off and again after it is turned back on.
For every VM, one SSH session answers repeated `date` requests. Each answer is
bracketed by host timestamps taken just before the request and just after the
reply, so the VM clock was read somewhere inside that interval:

    offset = vm_time - midpoint(host_before, host_after)
    bound  = (host_after - host_before) / 2      (the offset is within +/- bound)

The sample with the smallest round trip is kept. The export checks that distinct before/after samples bracket the capture.
Endpoint calibration still assumes no unobserved clock steps or excursions
inside the session; it does not measure or prove their absence.

Usage (host, NAT on):
  python -m tools.lab_clock_check --out D:/lab-rerec/<session-id>/clock-before.json
"""
import argparse
import json
import math
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
    if not isinstance(samples, int) or isinstance(samples, bool) or samples < 1:
        raise ValueError("samples must be a positive integer")
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
            vm_time = float(line)
            if not all(math.isfinite(v) for v in (before, vm_time, after)) or after < before:
                raise ValueError("clock sample must be finite with a nonnegative round trip")
            rows.append((before, vm_time, after))
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    rows = rows[1:]
    before, vm, after = min(rows, key=lambda row: row[2] - row[0])
    return {"offset_seconds": round(vm - (before + after) / 2, 6), "bound_seconds": math.ceil(((after - before) / 2 + 0.0000005) * 1_000_000) / 1_000_000,
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
    if args.samples < 1:
        ap.error("--samples must be positive")
    output = Path(args.out)
    if output.exists():
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = check(samples=args.samples)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, allow_nan=False)
        handle.write("\n")
    print(json.dumps(result["vms"], indent=2))


if __name__ == "__main__":
    main()
