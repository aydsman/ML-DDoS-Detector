import json
import subprocess

import pytest

from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_contract import BlockRequest, RuleState
from ddos_detector.firewall_state import FirewallState
from tools.check_firewall_poll import exercise_poll, main


class TestTransport:
    __test__ = False

    def __init__(self):
        self.rules = set()
        self.removed = []
        self.resets = 0
        self.unknown = False
        self.fail_inventory = False

    def check_inventory(self, requests, scope):
        if self.fail_inventory:
            raise ValueError("Foreign rule")

    def apply(self, request, scope):
        self.rules.add(request.block_id)

    def verify(self, request, scope):
        if self.unknown:
            return RuleState.UNKNOWN
        return RuleState.INSTALLED if request.block_id in self.rules else RuleState.ABSENT

    def remove(self, request, scope):
        self.removed.append(request.block_id)
        self.rules.discard(request.block_id)

    def cleanup_empty_table(self):
        assert not self.rules
        self.resets += 1


def scope():
    return FirewallScope("enp0s8", "10.10.10.10", ("10.0.2.0/24",), True)


def test_lab_check_observes_external_removal_and_persists_retirement(tmp_path):
    transport, evidence = TestTransport(), {}
    path = tmp_path / "state.sqlite"
    with FirewallState(path) as store:
        adapter = FirewallAdapter(transport, scope(), state_store=store)
        exercise_poll(adapter, transport, evidence)
        assert len(evidence["installed"]["blocks"]) == 1
        assert evidence["after_external_removal"]["reserved_slots"] == 0
        assert evidence["after_external_removal"]["events"][-1]["operation"] == "verify"
        assert evidence["retired_id_rejected"] is True
        assert transport.removed == [evidence["request"]["block_id"]]
        assert transport.resets == 2
    with FirewallState(path) as store:
        adapter = FirewallAdapter(transport, scope(), state_store=store)
        assert adapter.reserved_count == 0
        with pytest.raises(ValueError, match="new block ID"):
            adapter.apply(BlockRequest(**evidence["request"]))


def test_failed_verification_retains_reservation_for_recovery():
    transport, evidence = TestTransport(), {}
    original_remove = transport.remove

    def lose_observation(request, scope):
        original_remove(request, scope)
        transport.unknown = True

    transport.remove = lose_observation
    adapter = FirewallAdapter(transport, scope())
    with pytest.raises(RuntimeError, match="did not release"):
        exercise_poll(adapter, transport, evidence)
    assert evidence["cleanup"]["reserved_slots"] == 1
    assert evidence["cleanup"]["uncertain_block_ids"] == [evidence["request"]["block_id"]]
    assert transport.resets == 0


def test_unexpected_inventory_never_changes_rules():
    transport = TestTransport()
    transport.fail_inventory = True
    with pytest.raises(ValueError, match="Foreign"):
        exercise_poll(FirewallAdapter(transport, scope()), transport, {})
    assert not transport.rules and not transport.removed and transport.resets == 0


def test_interruption_after_installation_cleans_up():
    transport, evidence = TestTransport(), {}
    original_remove = transport.remove
    calls = 0

    def interrupt_once(request, scope):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt
        original_remove(request, scope)

    transport.remove = interrupt_once
    with pytest.raises(KeyboardInterrupt):
        exercise_poll(FirewallAdapter(transport, scope()), transport, evidence)
    assert evidence["cleanup"]["reserved_slots"] == 0
    assert transport.resets == 2


def test_cli_requires_explicit_execute_before_creating_output(tmp_path):
    output = tmp_path / "check"
    with pytest.raises(SystemExit) as exc:
        main(["--config", "docs/policy-defaults.json", "--output", str(output)])
    assert exc.value.code == 2
    assert not output.exists()


def test_cli_refuses_to_overwrite_previous_evidence(tmp_path):
    with pytest.raises(FileExistsError):
        main(["--execute", "--config", "docs/policy-defaults.json", "--output", str(tmp_path)])


def test_cli_saves_revision_configuration_and_terminal_evidence(tmp_path, monkeypatch):
    from tools import check_firewall_poll as tool
    from pathlib import Path

    config = tmp_path / "lab.json"
    document = json.loads(Path("docs/policy-defaults.json").read_text())
    document["allowlist"]["verified"] = True
    config.write_text(json.dumps(document))
    monkeypatch.setattr(tool, "validate_lab_runtime", lambda scope, runner: None)
    monkeypatch.setattr(tool, "NftablesTransport", lambda runner: TestTransport())
    # Linux platform.platform() may call uname through subprocess.run.
    # Keep environment lookup separate from the Git command double below.
    monkeypatch.setattr(tool.platform, "platform", lambda: "test-platform")

    def git_only(arguments, **kwargs):
        assert arguments[0] == "git"
        return subprocess.CompletedProcess(arguments, 0, "a" * 40 if "rev-parse" in arguments else "", "")

    monkeypatch.setattr(tool.subprocess, "run", git_only)
    output = tmp_path / "evidence"
    assert main(["--execute", "--config", str(config), "--output", str(output)]) == 0
    evidence = json.loads((output / "check.json").read_text())
    assert evidence["status"] == "passed"
    assert evidence["platform"] == "test-platform"
    assert evidence["git_commit"] == "a" * 40 and evidence["git_dirty"] is False
    assert evidence["cleanup"]["reserved_slots"] == 0
    assert (output / "config.json").read_bytes() == config.read_bytes()
    assert len(evidence["config_sha256"]) == 64
    assert evidence["ended_at"].endswith("Z")
