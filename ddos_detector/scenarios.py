"""Bounded SYN/UDP scenarios for the isolated three-VM project lab.

The default is an offline plan. Live sending requires --execute on the attacker
VM and never uses spoofed sources, an unbounded flood, or background workers.
"""

import argparse
import csv
import json
import math
import platform
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, sleep
from uuid import uuid4

LAB_TARGET = "10.10.10.10"
LAB_SOURCE = "10.10.10.30"
MAX_RATE = 1000
MAX_DURATION = 60
MAX_PACKETS = 10000


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ScenarioSettings:
    protocol: str
    target: str = LAB_TARGET
    port: int = 80
    rate: float = 10
    duration: float = 5
    interface: str = "enp0s8"

    def __post_init__(self):
        if self.protocol not in {"syn", "udp"}:
            raise ValueError("Protocol must be syn or udp.")
        if self.target != LAB_TARGET:
            raise ValueError(f"Target must be the isolated lab server {LAB_TARGET}.")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Port must be an integer from 1 to 65535.")
        if not math.isfinite(self.rate) or not 1 <= self.rate <= MAX_RATE:
            raise ValueError(f"Rate must be between 1 and {MAX_RATE} packets/second.")
        if not math.isfinite(self.duration) or not 0 < self.duration <= MAX_DURATION:
            raise ValueError(f"Duration must be positive and at most {MAX_DURATION} seconds.")
        if math.ceil(self.rate * self.duration) > MAX_PACKETS:
            raise ValueError(f"A scenario must schedule at most {MAX_PACKETS} packets.")
        if not self.interface or self.interface.strip() != self.interface:
            raise ValueError("Supply the isolated lab interface name.")


def scheduled_slot_count(settings):
    """Count the half-open grid consistently for live and cancelled workloads."""
    interval = 1 / settings.rate
    planned = math.ceil(settings.duration * settings.rate)
    while planned and (planned - 1) * interval >= settings.duration:
        planned -= 1
    while planned * interval < settings.duration:
        planned += 1
    return planned


def build_packet(settings, index):
    """Construct IPv4 packets without transmitting anything or spoofing sources."""
    from scapy.all import IP, TCP, UDP, Raw

    packet = IP(src=LAB_SOURCE, dst=settings.target, id=(index - 1) % 65536)
    source_port = 49152 + (index - 1) % 16384
    if settings.protocol == "syn":
        packet /= TCP(sport=source_port, dport=settings.port, flags="S", seq=index % (2**32))
    else:
        packet /= UDP(sport=source_port, dport=settings.port) / Raw(b"COMP3670 lab scenario")
    return packet


def open_lab_sender(settings):
    """Validate the direct lab route before ARP or opening a sending socket."""
    if platform.system() != "Linux":
        raise ValueError("Live sending requires the isolated Linux attacker VM.")
    from scapy.all import Ether, conf, get_if_addr, get_if_hwaddr, getmacbyip

    interface, source, gateway = conf.route.route(settings.target)
    if (interface != settings.interface or source != LAB_SOURCE
            or gateway != "0.0.0.0" or get_if_addr(settings.interface) != LAB_SOURCE):
        raise ValueError("Expected a direct lab route on the selected interface with source 10.10.10.30.")
    destination_mac = getmacbyip(settings.target)
    if not destination_mac:
        raise ValueError("The protected server did not answer lab ARP; no scenario started.")
    ethernet = Ether(src=get_if_hwaddr(settings.interface), dst=destination_mac)
    socket = conf.L2socket(iface=settings.interface)

    class LabSender:
        def send(self, packet):
            frame = ethernet / packet
            written = socket.send(frame)
            if written != len(bytes(frame)):
                raise OSError("The lab socket did not accept the complete frame.")

        def close(self):
            socket.close()

    return LabSender()


class ScenarioExport:
    """Flush each send attempt; unfinished/crashed runs remain visibly running."""

    def __init__(self, output, settings):
        self.run_id = str(uuid4())
        self.directory = Path(output) / self.run_id
        self.directory.mkdir(parents=True, exist_ok=False)
        self.metadata = {
            "schema_version": "scenario-draft-1", "run_id": self.run_id,
            "traffic_type": f"controlled_{settings.protocol}",
            "settings": asdict(settings), "source_ip": LAB_SOURCE,
            "state": "running", "started_at": None, "stopped_at": None,
            "summary": None, "activity_file": "activity.csv", "error": None,
        }
        self.write_metadata()
        self.handle = (self.directory / "activity.csv").open("x", encoding="utf-8", newline="")
        self.fields = ["run_id", "packet_index", "started_at", "epoch_seconds",
                       "elapsed_ms", "ip_bytes", "outcome", "error_type"]
        self.writer = csv.DictWriter(self.handle, fieldnames=self.fields)
        self.writer.writeheader()
        self.handle.flush()

    def write_metadata(self):
        temporary = self.directory / "run.json.tmp"
        temporary.write_text(json.dumps(self.metadata, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        temporary.replace(self.directory / "run.json")

    def record(self, row):
        self.writer.writerow({"run_id": self.run_id, **row})
        self.handle.flush()

    def finish(self, records, summary, state):
        # Rebuild before publishing the summary: SIGINT may interrupt record().
        temporary = self.directory / "activity.csv.tmp"
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.fields)
            writer.writeheader()
            for row in records:
                writer.writerow({"run_id": self.run_id, **row})
        self.handle.close()
        temporary.replace(self.directory / "activity.csv")
        self.metadata.update(state=state, summary=summary, stopped_at=utc_now())
        self.write_metadata()

    def close(self):
        self.handle.close()

    def finish_setup_failure(self, settings, error):
        """Finalize only a failed pre-send setup, never an already started run."""
        if self.metadata["started_at"] is not None:
            raise ValueError("Cannot record a setup failure after the scenario starts.")
        interrupted = isinstance(error, KeyboardInterrupt)
        planned = scheduled_slot_count(settings)
        summary = {
            "scheduled_slots": planned, "attempted": 0, "sent": 0,
            "send_errors": 0, "unknown": 0, "skipped_due_to_lag": 0,
            "cancelled_slots": planned, "elapsed_seconds": 0.0,
            "achieved_packets_per_second": 0.0, "interrupted": interrupted,
        }
        self.metadata["error"] = {
            "phase": "setup", "type": type(error).__name__,
            "message": str(error) or "Interrupted before the scenario started.",
        }
        state = "interrupted" if interrupted else "failed"
        self.finish([], summary, state)
        return state, summary


def run_scenario(settings, sender, export):
    """One fixed-grid sender, no catch-up bursts; drain no background work."""
    records = []
    export.metadata["started_at"] = utc_now()
    export.write_metadata()
    start = perf_counter()
    interval = 1 / settings.rate
    planned = scheduled_slot_count(settings)
    slot = 0
    interrupted = False
    failed = False
    skipped = 0
    try:
        while slot < planned:
            now = perf_counter() - start
            if now >= settings.duration:
                break
            due = slot * interval
            if now < due:
                sleep(due - now)
                now = perf_counter() - start
            if now >= settings.duration:
                break
            latest = min(planned - 1, max(slot, math.floor(now / interval)))
            skipped += latest - slot
            slot = latest
            packet = build_packet(settings, slot + 1)
            if perf_counter() - start >= settings.duration:
                break
            row = {
                "packet_index": slot + 1, "started_at": utc_now(),
                "epoch_seconds": None, "elapsed_ms": None,
                "ip_bytes": len(bytes(packet)), "outcome": "unknown",
                "error_type": None,
            }
            row["epoch_seconds"] = datetime.fromisoformat(row["started_at"]).timestamp()
            send_start = perf_counter()
            # Register before send so an interruption cannot hide an uncertain send.
            records.append(row)
            try:
                sender.send(packet)
                row["outcome"] = "sent"
            except KeyboardInterrupt:
                row.update(outcome="interrupted_unknown", error_type="KeyboardInterrupt")
                raise
            except Exception as exc:
                row.update(outcome="send_error", error_type=type(exc).__name__)
                failed = True
            finally:
                row["elapsed_ms"] = (perf_counter() - send_start) * 1000
            export.record(row)
            slot += 1
            if failed:
                break
        # Keep the requested observation window even when the last slot is early.
        if not failed:
            remaining_time = settings.duration - (perf_counter() - start)
            if remaining_time > 0:
                sleep(remaining_time)
    except KeyboardInterrupt:
        interrupted = True
    elapsed = perf_counter() - start
    remaining = planned - len(records) - skipped
    cancelled = remaining if interrupted or failed else 0
    if not interrupted and not failed:
        skipped += remaining
    sent = sum(row["outcome"] == "sent" for row in records)
    summary = {
        "scheduled_slots": planned, "attempted": len(records), "sent": sent,
        "send_errors": sum(row["outcome"] == "send_error" for row in records),
        "unknown": sum(row["outcome"] in {"unknown", "interrupted_unknown"} for row in records),
        "skipped_due_to_lag": skipped, "cancelled_slots": cancelled,
        "elapsed_seconds": elapsed,
        "achieved_packets_per_second": sent / elapsed if elapsed else 0.0,
        "interrupted": interrupted,
    }
    state = "interrupted" if interrupted else "failed" if failed else "complete"
    export.finish(records, summary, state)
    return state, summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, choices=["syn", "udp"])
    parser.add_argument("--target", default=LAB_TARGET)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rate", type=float, default=10)
    parser.add_argument("--duration", type=float, default=5)
    parser.add_argument("--interface", default="enp0s8")
    parser.add_argument("--output", type=Path, default=Path("results/scenarios"))
    parser.add_argument("--execute", action="store_true", help="Send on the isolated Linux lab; default only prints a plan")
    args = parser.parse_args(argv)
    try:
        settings = ScenarioSettings(args.protocol, args.target, args.port, args.rate, args.duration, args.interface)
    except ValueError as exc:
        parser.error(str(exc))
    if not args.execute:
        print(json.dumps({"mode": "plan_only", "settings": asdict(settings),
                          "source_ip": LAB_SOURCE, "packet_budget": scheduled_slot_count(settings)}, indent=2))
        return 0
    export = None
    sender = None
    try:
        export = ScenarioExport(args.output, settings)
        try:
            sender = open_lab_sender(settings)
        except (Exception, KeyboardInterrupt) as exc:
            # This handler is deliberately limited to pre-send setup. A later
            # export failure must retain actual activity, not publish zero sends.
            state, summary = export.finish_setup_failure(settings, exc)
            print(json.dumps({"run_id": export.run_id, "state": state,
                              "export_directory": str(export.directory.resolve()),
                              "summary": summary, "error": export.metadata["error"]}, indent=2))
            if state == "interrupted":
                return 130
            parser.exit(2, f"Scenario setup failed: {exc}. Saved failure record in {export.directory.resolve()}\n")
        state, summary = run_scenario(settings, sender, export)
        print(json.dumps({"run_id": export.run_id, "state": state,
                          "export_directory": str(export.directory.resolve()), "summary": summary}, indent=2))
        return 130 if state == "interrupted" else 1 if state == "failed" else 0
    except (OSError, ValueError) as exc:
        # Keep running/null-summary metadata on export failure; never fake completion.
        parser.exit(2, f"Scenario failed: {exc}. Any unfinished export is incomplete.\n")
    except KeyboardInterrupt:
        return 130
    finally:
        if sender is not None:
            sender.close()
        if export is not None:
            export.close()


if __name__ == "__main__":
    raise SystemExit(main())
