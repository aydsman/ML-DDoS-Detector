"""Explicit lab requests and restart-safe polling, separate from ML inference."""
import argparse
from datetime import datetime
import json
import math
from pathlib import Path
import time

from .firewall import FirewallAdapter, FirewallScope
from .firewall_contract import BlockRequest, RuleState
from .firewall_nft import NftablesTransport, validate_lab_runtime
from .firewall_state import FirewallState


def load_settings(path):
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document["schema"] != "policy-defaults-draft-1":
        raise ValueError("Unsupported policy configuration")
    scope = document["scope"]
    if scope["ip_version"] != 4 or scope["inbound_only"] is not True:
        raise ValueError("Expected inbound IPv4 lab scope")
    return FirewallScope(scope["capture_interface"], scope["protected_ip"],
                         tuple(row["address"] for row in document["allowlist"]["entries"]),
                         document["allowlist"]["verified"]), document["blocks"]["max_active_blocks"]


def report(adapter):
    last_state = {event.block_id: event.rule_state for event in adapter.audit_events}
    pending = adapter.pending_requests
    blocks = [{"id": block.request.block_id, "source_ip": block.request.source_ip,
               "reason": block.request.reason,
               "blocked_at": block.blocked_at.isoformat().replace("+00:00", "Z"),
               "expires_at": block.expires_at.isoformat().replace("+00:00", "Z")}
              for block in adapter.confirmed_blocks
              if last_state.get(block.request.block_id) == RuleState.INSTALLED]
    blocks.sort(key=lambda block: (-datetime.fromisoformat(block["blocked_at"]).timestamp(), block["id"]))
    return {"reserved_slots": len(pending), "blocks": blocks,
            "uncertain_block_ids": sorted(request.block_id for request in pending
                                          if last_state.get(request.block_id) != RuleState.INSTALLED),
            "events": list(adapter.audit_records)}


def poll(adapter, interval, *, sleep=time.sleep):
    """Run until all pending actions resolve or the operator interrupts."""
    while adapter.reserved_count:
        adapter.expire_due()
        if adapter.reserved_count:
            sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("apply", "reconcile", "cleanup", "status"))
    parser.add_argument("--config", default="docs/policy-defaults.json")
    parser.add_argument("--state", default="results/firewall/state.sqlite")
    parser.add_argument("--requests", help="JSON array of explicit BlockRequest objects")
    parser.add_argument("--execute", action="store_true", help="Explicitly authorize live lab firewall access")
    parser.add_argument("--poll-seconds", type=float, default=1)
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("Live lab access requires --execute and verified configuration")
    if not math.isfinite(args.poll_seconds) or not 0.1 <= args.poll_seconds <= 5:
        parser.error("Polling interval must be between 0.1 and 5 seconds")
    if bool(args.requests) != (args.action == "apply"):
        parser.error("--requests is required only for apply")
    try:
        scope, capacity = load_settings(args.config)
        validate_lab_runtime(scope)
        requests = []
        if args.requests:
            rows = json.loads(Path(args.requests).read_text(encoding="utf-8"))
            if not isinstance(rows, list):
                raise ValueError("Requests must be a JSON array")
            requests = [BlockRequest(**row) for row in rows]
            # Validate the entire batch before any firewall mutation.
            for request in requests:
                scope.check_source(request.source_ip)
        transport = NftablesTransport()
        with FirewallState(args.state) as store:
            adapter = FirewallAdapter(transport, scope, capacity, state_store=store)
            transport.check_inventory(adapter.pending_requests, scope)
            adapter.reconcile()
            adapter.validate_batch(requests)
            try:
                if args.action == "cleanup":
                    adapter.cleanup()
                elif args.action == "apply":
                    for request in requests:
                        adapter.apply(request)
                if args.action != "status":
                    poll(adapter, args.poll_seconds)
                if args.action == "cleanup" and not adapter.reserved_count:
                    transport.cleanup_empty_table()
            except KeyboardInterrupt:
                # Cleanup is verified; any unresolved rules stay journaled.
                adapter.cleanup()
                print(json.dumps(report(adapter), indent=2))
                return 130
            print(json.dumps(report(adapter), indent=2))
            failed = any(not result.success for result in adapter.audit_events)
            unresolved = args.action != "status" and adapter.reserved_count > 0
            return 2 if failed or unresolved else 0
    except Exception as exc:
        parser.exit(2, f"Firewall operation stopped: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
