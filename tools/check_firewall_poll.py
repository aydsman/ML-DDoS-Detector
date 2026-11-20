"""Explicit isolated-lab check for external rule disappearance; no traffic sent."""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from uuid import uuid4

from ddos_detector.firewall import FirewallAdapter
from ddos_detector.firewall_cli import load_settings, report
from ddos_detector.firewall_contract import BlockRequest
from ddos_detector.firewall_nft import NftablesTransport, validate_lab_runtime
from ddos_detector.firewall_state import FirewallState


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def exercise_poll(adapter, transport, evidence):
    """Remove one exact test rule outside the adapter, then poll before expiry."""
    if adapter.reserved_count:
        raise ValueError("Use a new, empty test journal")
    transport.check_inventory((), adapter.scope)
    request = BlockRequest("poll-check-" + str(uuid4()), "10.10.10.30",
                           "Explicit external-disappearance lab check", 300)
    evidence["request"] = asdict(request)
    try:
        result = adapter.apply(request)
        evidence["installed"] = report(adapter)
        if not result.success:
            raise RuntimeError("Test rule installation was not verified")
        expires_at = adapter.confirmed_blocks[0].expires_at
        # Deliberately bypass adapter.remove: its next poll must discover this.
        transport.remove(request, adapter.scope)
        adapter.expire_due()
        evidence["after_external_removal"] = report(adapter)
        if adapter.clock() >= expires_at:
            raise RuntimeError("Check took too long to establish pre-expiry disappearance")
        if adapter.reserved_count or evidence["after_external_removal"]["blocks"]:
            raise RuntimeError("Polling did not release the externally removed rule")
        try:
            adapter.apply(request)
        except ValueError as exc:
            if "new block ID" not in str(exc):
                raise
        else:
            raise RuntimeError("Retired action ID was unexpectedly reused")
        evidence["retired_id_rejected"] = True
    finally:
        # Retain the journal if observation/removal fails. Never flush a ruleset.
        adapter.cleanup()
        evidence["cleanup"] = report(adapter)
        if not adapter.reserved_count:
            transport.cleanup_empty_table()
            transport.cleanup_empty_table()
            evidence["repeat_cleanup_passed"] = True
    if any(not event.success for event in adapter.audit_events):
        raise RuntimeError("A firewall observation failed; inspect the retained audit")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory; refuses existing paths")
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("This live lab check requires --execute and an owner-verified local configuration")
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {"schema": "firewall-poll-check-1", "status": "running", "started_at": utc_now(),
                "python": platform.python_version(), "platform": platform.platform(), "commands": []}
    destination = args.output / "check.json"

    def save():
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        temporary.replace(destination)

    def runner(arguments, **kwargs):
        result = subprocess.run(arguments, **kwargs)
        evidence["commands"].append({"argv": arguments, "input": kwargs.get("input"),
                                     "returncode": result.returncode, "stdout": result.stdout,
                                     "stderr": result.stderr, "observed_at": utc_now()})
        save()
        return result

    save()
    exit_code = 2
    try:
        revision = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        evidence["git_commit"] = revision.stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=True)
        evidence["git_dirty"] = bool(dirty.stdout.strip())
        config_bytes = args.config.read_bytes()
        (args.output / "config.json").write_bytes(config_bytes)
        evidence["config_sha256"] = hashlib.sha256(config_bytes).hexdigest()
        scope, capacity = load_settings(args.output / "config.json")
        validate_lab_runtime(scope, runner=runner)
        transport = NftablesTransport(runner=runner)
        with FirewallState(args.output / "state.sqlite") as store:
            adapter = FirewallAdapter(transport, scope, capacity, state_store=store)
            exercise_poll(adapter, transport, evidence)
        evidence["status"], exit_code = "passed", 0
    except KeyboardInterrupt:
        evidence["status"], evidence["error"], exit_code = "interrupted", "KeyboardInterrupt", 130
    except Exception as exc:
        evidence["status"], evidence["error"] = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        evidence["ended_at"] = utc_now()
        save()
    print(destination.resolve())
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
