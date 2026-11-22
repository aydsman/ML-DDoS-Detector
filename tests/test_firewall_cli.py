import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_cli import load_settings, main, poll, report
from ddos_detector.firewall_contract import BlockRequest, RuleState
from test_firewall import FakeFirewall


def test_live_entry_point_rejects_default_unverified_settings():
    with pytest.raises(SystemExit) as error:
        main(["status", "--execute"])
    assert error.value.code == 2


def test_entry_point_requires_explicit_execute():
    with pytest.raises(SystemExit) as error:
        main(["cleanup"])
    assert error.value.code == 2


def test_policy_defaults_remain_unverified():
    scope, capacity = load_settings(Path(__file__).resolve().parents[1] / "docs/policy-defaults.json")
    assert scope.verified is False
    assert capacity == 20


def test_poll_drives_expiry_and_reports_original_api_fields():
    now = datetime(2026, 11, 14, tzinfo=timezone.utc)
    adapter = FirewallAdapter(FakeFirewall(), FirewallScope("enp0s8", "10.10.10.10", (), True),
                              clock=lambda: now)
    request = BlockRequest("a", "10.10.10.30", "Manual test", 2)
    adapter.apply(request)
    before = report(adapter)
    assert before["blocks"][0]["id"] == "a"
    assert before["blocks"][0]["blocked_at"] == "2026-11-14T00:00:00Z"
    assert before["blocks"][0]["expires_at"] == "2026-11-14T00:00:02Z"

    def advance(seconds):
        nonlocal now
        now += timedelta(seconds=seconds)

    poll(adapter, 1, sleep=advance)
    assert report(adapter)["reserved_slots"] == 0
    assert report(adapter)["blocks"] == []
    assert report(adapter)["events"][-1]["operation"] == "expire"


def test_cli_manual_apply_uses_journal_and_polls_to_verified_removal(tmp_path, monkeypatch, capsys):
    from ddos_detector import firewall_cli
    document = json.loads((Path(__file__).resolve().parents[1] / "docs/policy-defaults.json").read_text())
    document["allowlist"]["verified"] = True
    config = tmp_path / "lab.json"
    config.write_text(json.dumps(document))
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps([{"block_id": "a", "source_ip": "10.10.10.30",
                                     "reason": "Manual test", "duration_seconds": 300}]))
    firewall = FakeFirewall()
    firewall.check_inventory = lambda requests, scope: None
    monkeypatch.setattr(firewall_cli, "validate_lab_runtime", lambda scope: None)
    monkeypatch.setattr(firewall_cli, "NftablesTransport", lambda: firewall)
    monkeypatch.setattr(firewall_cli, "poll", lambda adapter, interval: adapter.cleanup())
    assert main(["apply", "--execute", "--config", str(config), "--requests", str(requests),
                 "--state", str(tmp_path / "state.sqlite")]) == 0
    assert json.loads(capsys.readouterr().out)["reserved_slots"] == 0
    assert len(firewall.applied) == len(firewall.removed) == 1


def test_cli_reports_failed_installation_and_returns_failure(tmp_path, monkeypatch, capsys):
    from ddos_detector import firewall_cli
    document = json.loads((Path(__file__).resolve().parents[1] / "docs/policy-defaults.json").read_text())
    document["allowlist"]["verified"] = True
    config = tmp_path / "lab.json"
    config.write_text(json.dumps(document))
    requests = tmp_path / "requests.json"
    requests.write_text(json.dumps([{"block_id": "a", "source_ip": "10.10.10.30", "reason": "Manual"}]))
    firewall = FakeFirewall()
    firewall.apply_error = PermissionError("Denied")
    firewall.check_inventory = lambda requests, scope: None
    monkeypatch.setattr(firewall_cli, "validate_lab_runtime", lambda scope: None)
    monkeypatch.setattr(firewall_cli, "NftablesTransport", lambda: firewall)
    assert main(["apply", "--execute", "--config", str(config), "--requests", str(requests),
                 "--state", str(tmp_path / "state.sqlite")]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["events"][0]["success"] is False
    assert "PermissionError" in output["events"][0]["error"]


def test_report_distinguishes_uncertain_rule_from_confirmed_block():
    firewall = FakeFirewall()
    adapter = FirewallAdapter(firewall, FirewallScope("enp0s8", "10.10.10.10", (), True))
    request = BlockRequest("a", "10.10.10.30", "Manual test")
    assert adapter.apply(request).success
    original, = adapter.confirmed_blocks

    firewall.verify_error = TimeoutError("Verification unavailable")
    assert adapter.verify(request).rule_state == RuleState.UNKNOWN
    uncertain = report(adapter)
    assert uncertain["blocks"] == []
    assert uncertain["uncertain_block_ids"] == ["a"]
    assert uncertain["reserved_slots"] == 1

    firewall.verify_error = None
    assert adapter.verify(request).rule_state == RuleState.INSTALLED
    confirmed = report(adapter)
    assert confirmed["blocks"][0]["id"] == "a"
    assert confirmed["uncertain_block_ids"] == []
    assert adapter.confirmed_blocks == (original,)

def test_poll_detects_external_removal_before_expiry():
    firewall = FakeFirewall()
    now = datetime(2026, 11, 17, tzinfo=timezone.utc)
    adapter = FirewallAdapter(firewall, FirewallScope("enp0s8", "10.10.10.10", (), True),
                              clock=lambda: now)
    request = BlockRequest("a", "10.10.10.30", "Manual test")
    assert adapter.apply(request).success

    firewall.verify_error = TimeoutError("Verification unavailable")
    assert adapter.expire_due() == ()
    assert report(adapter)["uncertain_block_ids"] == ["a"]
    assert adapter.reserved_count == 1

    firewall.verify_error = None
    firewall.state = RuleState.ABSENT
    assert adapter.expire_due() == ()
    assert report(adapter)["blocks"] == []
    assert report(adapter)["uncertain_block_ids"] == []
    assert adapter.reserved_count == 0
    assert firewall.removed == []
