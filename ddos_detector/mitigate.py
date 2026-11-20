"""W4 policy runner: offline monitor-only replay or explicitly enabled lab enforcement."""
import argparse
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time

from .config import Config
from .enforcement import Enforcement, PolicySettings, SourcePolicy, finite
from .firewall import FirewallAdapter
from .firewall_cli import settings_from_document
from .firewall_nft import NftablesTransport, validate_lab_runtime
from .firewall_state import FirewallState
from .live import LivePipeline
from .monitor import Monitor
from .pcap import read_pcap
from .training import load_model


def run_source(source, pipeline, monitor, controller, *, replay=False, poll_seconds=1,
               monotonic=time.monotonic):
    """Poll independently of window emission, including busy/filtered/idle capture."""
    deadline = monotonic()

    def observed_source():
        nonlocal deadline
        for item in source:
            now = monotonic()
            if not replay and now >= deadline:
                controller.tick()
                deadline = now + poll_seconds
            yield item

    try:
        monitor.status(pipeline, "started")
        for record in pipeline.run(observed_source(), flush_at_end=replay):
            monitor.handle(record)
        # A source error is recorded by LivePipeline; no further partial window
        # can qualify. The owner performs cleanup in the outer finally block.
        if not replay and pipeline.status == "ok":
            for record in pipeline.stop():
                monitor.handle(record)
        monitor.status(pipeline, "completed" if pipeline.status == "ok" else "unavailable")
        return 0 if pipeline.status == "ok" else 2
    finally:
        controller.policy.reset()
        close = getattr(source, "close", None)
        if close is not None:
            close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface")
    source.add_argument("--replay", type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--config", type=Path, default=Path("docs/policy-defaults.json"))
    parser.add_argument("--log", type=Path, required=True, help="New JSONL audit file")
    parser.add_argument("--state", type=Path, default=Path("results/firewall/state.sqlite"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--duration", type=float)
    parser.add_argument("--poll-seconds", type=float, default=1)
    args = parser.parse_args(argv)
    controller = None
    try:
        finite(args.poll_seconds, "Polling interval", 0.1)
        if args.poll_seconds > 5:
            raise ValueError("Polling interval must be <= 5 seconds")
        if args.duration is not None:
            finite(args.duration, "Capture duration", 0.001)
        config_bytes = args.config.read_bytes()
        document = json.loads(config_bytes)
        settings = PolicySettings.from_document(document)
        scope, capacity = settings_from_document(document)
        mode = document["mode"]
        if mode not in {"automatic", "monitor_only"}:
            raise ValueError("Unsupported mitigation mode")
        automatic = mode == "automatic"
        if automatic:
            if not args.execute or not args.interface or args.replay:
                raise ValueError("Automatic mode requires live --interface and explicit --execute; replay cannot enforce")
            settings.require_automatic(scope)
        elif args.execute:
            raise ValueError("--execute requires an approved automatic configuration")
        if args.interface and args.interface != scope.interface:
            raise ValueError("Capture interface differs from the policy/firewall scope")
        loaded_model = load_model(args.model)
        if automatic and loaded_model[1]["data"]["data_kind"] != "reviewed_packet_windows":
            raise ValueError("Automatic mode requires a reviewed packet-window model, not a synthetic demo")
        with ExitStack() as stack:
            log = stack.enter_context(args.log.open("x", encoding="utf-8"))

            def emit(event):
                event = {"logged_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **event}
                log.write(json.dumps(event, allow_nan=False) + "\n")
                log.flush()

            emit({"record_type": "enforcement_run", "mode": mode,
                  "config": document, "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
                  "model_sha256": loaded_model[1]["model_sha256"],
                  "source_mode": "replay" if args.replay else "live"})
            adapter = None
            if automatic:
                validate_lab_runtime(scope)
                store = stack.enter_context(FirewallState(args.state))
                transport = NftablesTransport()
                adapter = FirewallAdapter(transport, scope, capacity, state_store=store, audit_limit=capacity * 2)
                transport.check_inventory(adapter.pending_requests, scope)
            controller = Enforcement(SourcePolicy(settings, scope), emit, mode=mode, adapter=adapter)
            # Keep cleanup inside the journal/log lifetimes, including startup Ctrl+C.
            try:
                if adapter is not None:
                    adapter.reconcile()
                    controller.tick()
                config = replace(Config(), victim_ip=scope.protected_ip,
                                 grace_seconds=finite(document["window"]["grace_seconds"], "Grace period"))
                pipeline = LivePipeline(config)
                monitor = Monitor(args.model, log, 1, live=bool(args.interface),
                                  loaded_model=loaded_model, deliver=controller.handle,
                                  monitor_only=not automatic)
                if args.replay:
                    frames = read_pcap(args.replay)
                else:
                    from .capture import capture_frames
                    frames = capture_frames(args.interface, timeout=min(0.5, args.poll_seconds), duration=args.duration)
                result = run_source(frames, pipeline, monitor, controller, replay=bool(args.replay),
                                    poll_seconds=args.poll_seconds)
            except KeyboardInterrupt:
                emit({"record_type": "enforcement_stop", "reason": "interrupted", "mode": mode})
                result = 130
            except Exception as exc:
                emit({"record_type": "enforcement_error", "mode": mode,
                      "error": f"{type(exc).__name__}: {exc}"})
                raise
            finally:
                if not controller.cleanup():
                    raise RuntimeError("Cleanup unresolved; retain the journal and reconcile before another trial")
            if adapter is not None and adapter.had_failures and result == 0:
                result = 2
            emit({"record_type": "enforcement_stop", "reason": "completed" if result == 0 else "stopped",
                  "mode": mode, "exit_code": result})
            return result
    except Exception as exc:
        print(f"Mitigation stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
