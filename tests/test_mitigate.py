from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from ddos_detector import mitigate, monitor, capture
from ddos_detector.firewall import FirewallAdapter
from ddos_detector.firewall_cli import settings_from_document
from ddos_detector.firewall_contract import BlockRequest
from ddos_detector.firewall_state import FirewallState
from ddos_detector.live import LivePipeline
from test_enforcement import Rules
from test_frames import eth, ipv4


def document():
    return json.loads(Path("docs/policy-defaults.json").read_text())


def write_config(tmp_path, automatic=True):
    doc = document()
    if automatic:
        doc.update(mode="automatic", policy_review_ref="synthetic fixture only", max_window_age_seconds=5)
        doc["allowlist"]["verified"] = True
        doc["attribution"].update(min_share=0.1, syn_rate_threshold=1,
                                  packet_rate_thresholds={"tcp": 1, "udp": None, "icmp": None})
    path = tmp_path / "config.json"
    path.write_text(json.dumps(doc))
    return path, doc


@pytest.fixture
def runtime(monkeypatch):
    rules = Rules()
    monkeypatch.setattr(mitigate, "load_model", lambda path: (None, {
        "data": {"data_kind": "reviewed_packet_windows"}, "model_sha256": "fixture-model"}))
    monkeypatch.setattr(monitor, "score_loaded_record", lambda *args: {
        "attack_score": 0.9, "predicted_attack": True, "decision_threshold": 0.5,
        "model_sha256": "fixture-model", "data_kind": "reviewed_packet_windows"})
    monkeypatch.setattr(mitigate, "validate_lab_runtime", lambda scope: None)
    monkeypatch.setattr(mitigate, "NftablesTransport", lambda: rules)
    monkeypatch.setattr(mitigate, "FirewallAdapter", lambda *args, **kwargs: FirewallAdapter(
        *args, **kwargs, clock=lambda: datetime.fromtimestamp(105, timezone.utc)))
    monkeypatch.setattr(mitigate, "LivePipeline", lambda config: LivePipeline(config, clock=lambda: 105))

    def frames(*args, **kwargs):
        for second in range(100, 104):
            for _ in range(3):
                yield second + 0.1, eth(0x0800, ipv4())
        yield None

    monkeypatch.setattr(capture, "capture_frames", frames)
    return rules


def arguments(config, log, state):
    return ["--interface", "enp0s8", "--execute", "--model", "fixture",
            "--config", str(config), "--log", str(log), "--state", str(state)]


def test_complete_capture_score_policy_firewall_and_repeat_reset(tmp_path, runtime):
    config, _ = write_config(tmp_path)
    state = tmp_path / "state.sqlite"
    for number in (1, 2):
        log = tmp_path / f"trial-{number}.jsonl"
        assert mitigate.main(arguments(config, log, state)) == 0
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        requests = [r for r in rows if r["record_type"] == "block_requested"]
        assert len(requests) == 1 and requests[0]["source_ip"] == "10.10.10.30"
        assert requests[0]["window_start"] == 102
        assert all(r["monitor_only"] is False for r in rows if r["record_type"] == "window")
        assert rows[-1]["exit_code"] == 0
        assert not runtime.rules and runtime.resets == number
    assert len(runtime.installs) == 2 and runtime.installs[0].block_id != runtime.installs[1].block_id


def test_monitor_only_does_not_construct_or_validate_firewall(tmp_path, runtime, monkeypatch):
    config, _ = write_config(tmp_path, automatic=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("Monitor-only must not touch the firewall")

    monkeypatch.setattr(mitigate, "validate_lab_runtime", forbidden)
    monkeypatch.setattr(mitigate, "NftablesTransport", forbidden)
    log = tmp_path / "preview.jsonl"
    assert mitigate.main(["--interface", "enp0s8", "--model", "fixture", "--config", str(config), "--log", str(log)]) == 0
    assert not any(json.loads(line)["record_type"] == "block_requested" for line in log.read_text().splitlines())


@pytest.mark.parametrize("failure", ["capture", "interrupt", "scoring"])
def test_failure_after_installation_cleans_up(tmp_path, runtime, monkeypatch, failure):
    original = capture.capture_frames

    def broken(*args, **kwargs):
        yield from original(*args, **kwargs)
        if failure == "interrupt":
            raise KeyboardInterrupt
        if failure == "capture":
            raise OSError("test capture unavailable")
        yield 106.1, eth(0x0800, ipv4())
        yield 107.1, eth(0x0800, ipv4())
        yield 108.1, eth(0x0800, ipv4())

    if failure == "scoring":
        score = monitor.score_loaded_record
        calls = 0

        def fails_later(*args):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise RuntimeError("test scoring failure")
            return score(*args)

        monkeypatch.setattr(monitor, "score_loaded_record", fails_later)
    monkeypatch.setattr(capture, "capture_frames", broken)
    config, _ = write_config(tmp_path)
    assert mitigate.main(arguments(config, tmp_path / "audit.jsonl", tmp_path / "state.sqlite")) == (130 if failure == "interrupt" else 2)
    assert runtime.installs and not runtime.rules and runtime.resets == 1


def test_startup_interrupt_cleans_saved_reservation(tmp_path, runtime, monkeypatch):
    config, doc = write_config(tmp_path)
    scope, capacity = settings_from_document(doc)
    state = tmp_path / "state.sqlite"
    with FirewallState(state) as store:
        adapter = FirewallAdapter(runtime, scope, capacity, state_store=store)
        adapter.apply(BlockRequest("saved", "10.10.10.30", "test only"))

    def adapter_with_interrupt(*args, **kwargs):
        adapter = FirewallAdapter(*args, **kwargs)

        def interrupt():
            raise KeyboardInterrupt

        adapter.reconcile = interrupt
        return adapter

    monkeypatch.setattr(mitigate, "FirewallAdapter", adapter_with_interrupt)
    assert mitigate.main(arguments(config, tmp_path / "audit.jsonl", state)) == 130
    assert not runtime.rules
    with FirewallState(state) as store:
        assert FirewallAdapter(runtime, scope, capacity, state_store=store).reserved_count == 0


@pytest.mark.parametrize("gate", ["no_execute", "replay", "unverified", "no_review", "null_share", "synthetic_model", "wrong_nic"])
def test_automatic_gates_reject_before_firewall_access(tmp_path, runtime, monkeypatch, gate):
    config, doc = write_config(tmp_path)
    log = tmp_path / "never.jsonl"
    args = arguments(config, log, tmp_path / "state.sqlite")
    if gate == "no_execute":
        args.remove("--execute")
    elif gate == "replay":
        args[:2] = ["--replay", "unused.pcap"]
    elif gate == "unverified":
        doc["allowlist"]["verified"] = False
    elif gate == "no_review":
        doc["policy_review_ref"] = None
    elif gate == "null_share":
        doc["attribution"]["min_share"] = None
    elif gate == "synthetic_model":
        monkeypatch.setattr(mitigate, "load_model", lambda path: (None, {"data": {"data_kind": "synthetic"}}))
    else:
        args[1] = "enp0s3"
    config.write_text(json.dumps(doc))
    assert mitigate.main(args) == 2
    assert not runtime.installs and not log.exists()


def test_existing_audit_is_never_overwritten(tmp_path, runtime):
    config, _ = write_config(tmp_path)
    log = tmp_path / "existing.jsonl"
    log.write_text("original")
    assert mitigate.main(arguments(config, log, tmp_path / "state.sqlite")) == 2
    assert log.read_text() == "original" and not runtime.installs


def test_saved_pcap_replay_runs_policy_without_firewall(tmp_path, runtime):
    config, _ = write_config(tmp_path, automatic=False)
    log = tmp_path / "replay.jsonl"
    assert mitigate.main(["--replay", "tests/fixtures/week2/synthetic-mixed-boundaries.pcap",
                          "--model", "fixture", "--config", str(config), "--log", str(log)]) == 0
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert rows[0]["source_mode"] == "replay"
    assert any(r["record_type"] == "policy_window" for r in rows)
    assert not runtime.installs


def test_idle_capture_ticks_expiry_without_any_finished_window():
    from ddos_detector.enforcement import Enforcement, SourcePolicy
    from test_enforcement import settings, scope
    now = [100.0]
    rules = Rules()
    adapter = FirewallAdapter(rules, scope(), clock=lambda: datetime.fromtimestamp(now[0], timezone.utc))
    adapter.apply(BlockRequest("idle", "10.10.10.30", "test", 2))
    controller = Enforcement(SourcePolicy(settings(), scope()), lambda event: None, mode="automatic", adapter=adapter)

    class NoWindows:
        def status(self, *args):
            pass

        def handle(self, record):
            raise AssertionError("No window should be needed for expiry")

    def idle():
        for _ in range(3):
            now[0] += 1
            yield None

    assert mitigate.run_source(idle(), LivePipeline(clock=lambda: now[0]), NoWindows(), controller,
                                monotonic=lambda: now[0]) == 0
    assert adapter.reserved_count == 0 and not rules.rules


def test_sigterm_after_installation_cleans_rules_and_restores_handler(tmp_path, runtime, monkeypatch):
    import signal
    original_frames = capture.capture_frames
    prior = object()
    handlers = []
    monkeypatch.setattr(mitigate.signal, "getsignal", lambda number: prior)
    monkeypatch.setattr(mitigate.signal, "signal", lambda number, handler: handlers.append((number, handler)))

    def terminated(*args, **kwargs):
        yield from original_frames(*args, **kwargs)
        assert runtime.rules  # the signal arrives after an actual fixture install
        handlers[-1][1](signal.SIGTERM, None)

    monkeypatch.setattr(capture, "capture_frames", terminated)
    config, _ = write_config(tmp_path)
    log = tmp_path / "terminated.jsonl"
    assert mitigate.main(arguments(config, log, tmp_path / "state.sqlite")) == 130
    assert not runtime.rules and runtime.resets == 1
    assert handlers[-1] == (signal.SIGTERM, prior)
    assert json.loads(log.read_text().splitlines()[-1])["exit_code"] == 130
