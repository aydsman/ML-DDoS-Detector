"""Check that a lab VM can keep the policy-session schedule (docs/lab-policy-sessions.md), sending nothing.

Runs the real schedulers at the session rates: the attacker's scenario loop
against a no-op sender, and the client's HTTP loop against a mock transport.
Nothing leaves the VM, so it is safe with NAT on.

Pass thresholds come from the original sessions (lab-handoff.zip on issue #3):
the weakest original attack run sent 8,920 of 9,600 slots (92.9%), and the
client completed every scheduled request (18,600 of 18,600).

Usage:
  python -m tools.lab_timing_check --role attacker   # 160 packets/s for 20 s
  python -m tools.lab_timing_check --role client     # 20 requests/s for 20 s
Exit code 0 means pass, 1 means the VM fell behind.
"""
import argparse
import json
import tempfile

import httpx

from ddos_detector import http_client, scenarios

ATTACK_RATE, CLIENT_RATE = 160.0, 20.0
ATTACK_MIN_SHARE, CLIENT_MIN_SHARE = 0.929, 0.98


class NullSender:
    """Stands in for the raw socket: builds the bytes, sends nothing."""

    def send(self, packet):
        bytes(packet)


def check_attacker(duration, rate=ATTACK_RATE):
    settings = scenarios.ScenarioSettings(protocol="syn", rate=rate, duration=duration)
    with tempfile.TemporaryDirectory() as folder:
        _, summary = scenarios.run_scenario(settings, NullSender(), scenarios.ScenarioExport(folder, settings))
    share = summary["sent"] / summary["scheduled_slots"]
    return {"role": "attacker", "rate": rate, "duration": duration, "scheduled": summary["scheduled_slots"],
            "delivered": summary["sent"], "skipped_due_to_lag": summary["skipped_due_to_lag"],
            "share": round(share, 4), "minimum_share": ATTACK_MIN_SHARE, "pass": share >= ATTACK_MIN_SHARE}


def check_client(duration, rate=CLIENT_RATE):
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        result = http_client.run_requests(client, http_client.ClientSettings("http://10.10.10.10/"),
                                          http_client.RunSettings(rate, duration))
    share = result.attempted / result.scheduled_slots if result.scheduled_slots else 0.0
    return {"role": "client", "rate": rate, "duration": duration, "scheduled": result.scheduled_slots,
            "delivered": result.attempted, "skipped_due_to_lag": result.skipped_due_to_lag,
            "share": round(share, 4), "minimum_share": CLIENT_MIN_SHARE, "pass": share >= CLIENT_MIN_SHARE}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--role", required=True, choices=["attacker", "client"])
    ap.add_argument("--duration", type=float, default=20.0, help="seconds (default 20)")
    args = ap.parse_args(argv)
    result = (check_attacker if args.role == "attacker" else check_client)(args.duration)
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
