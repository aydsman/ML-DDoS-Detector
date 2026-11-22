import copy
import json
from types import SimpleNamespace

import pytest

from ddos_detector.firewall import FirewallAdapter, FirewallScope
from ddos_detector.firewall_contract import BlockRequest, RuleState
from ddos_detector.firewall_nft import NftablesTransport, validate_lab_runtime


def scope():
    return FirewallScope("enp0s8", "10.10.10.10",
                         ("10.10.10.10", "10.10.10.20", "127.0.0.0/8", "10.0.2.0/24"), True)


def owned_ruleset(rule=None):
    rows = [
        {"table": {"family": "ip", "name": "ml_ddos_lab", "comment": "ml-ddos-detector-v1"}},
        {"chain": {"family": "ip", "table": "ml_ddos_lab", "name": "inbound", "type": "filter",
                   "hook": "input", "prio": -10, "policy": "accept"}},
    ]
    if rule is not None:
        rows.append({"rule": rule})
    return {"nftables": rows}


class Runner:
    def __init__(self, document):
        self.document = document
        self.calls = []
        self.error = False

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.error:
            return SimpleNamespace(returncode=1, stdout="", stderr="Operation not permitted")
        return SimpleNamespace(returncode=0, stdout=json.dumps(self.document), stderr="")


def request():
    return BlockRequest("manual-1", "10.10.10.30", "Manual test")


def test_apply_creates_only_owned_table_and_exact_lab_rule():
    runner = Runner({"nftables": []})
    transport = NftablesTransport(runner)
    transport.apply(request(), scope())
    argv, options = runner.calls[-1]
    assert argv == ["nft", "-j", "-f", "-"]
    commands = json.loads(options["input"])["nftables"]
    assert commands[0] == {"create": {"table": {"family": "ip", "name": "ml_ddos_lab",
                                               "comment": "ml-ddos-detector-v1"}}}
    assert commands[1]["add"]["chain"]["policy"] == "accept"
    rule = commands[2]["add"]["rule"]
    assert rule["expr"] == [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "enp0s8"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.10.10.10"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.10.10.30"}},
        {"drop": None},
    ]
    assert "shell" not in options
    assert options["timeout"] == 5


def test_verify_and_remove_use_exact_owned_rule_handle():
    runner = Runner({"nftables": []})
    transport = NftablesTransport(runner)
    rule = transport._rule(request(), scope())
    runner.document = owned_ruleset({**rule, "handle": 7})
    assert transport.verify(request(), scope()) == RuleState.INSTALLED
    transport.remove(request(), scope())
    command, = json.loads(runner.calls[-1][1]["input"])["nftables"]
    assert command == {"delete": {"rule": {"family": "ip", "table": "ml_ddos_lab",
                                          "chain": "inbound", "handle": 7}}}


def test_permission_failure_is_unknown_and_reserves_slot():
    runner = Runner({"nftables": []})
    runner.error = True
    adapter = FirewallAdapter(NftablesTransport(runner), scope())
    result = adapter.apply(request())
    assert result.rule_state == RuleState.UNKNOWN and not result.success
    assert adapter.reserved_count == 1
    assert all(options["input"] is None for _, options in runner.calls)


@pytest.mark.parametrize("tamper", ["owner", "scope", "duplicate", "orphan"])
def test_changed_or_orphan_rules_rejected_before_mutation(tamper):
    runner = Runner({"nftables": []})
    transport = NftablesTransport(runner)
    rule = {**transport._rule(request(), scope()), "handle": 7}
    runner.document = owned_ruleset(copy.deepcopy(rule))
    if tamper == "owner":
        runner.document["nftables"][0]["table"]["comment"] = "another-owner"
    elif tamper == "scope":
        runner.document["nftables"][2]["rule"]["expr"][0]["match"]["right"] = "enp0s3"
    elif tamper == "duplicate":
        runner.document["nftables"].append({"rule": rule})
    with pytest.raises(ValueError):
        transport.check_inventory([] if tamper == "orphan" else [request()], scope())
    assert all(options["input"] is None for _, options in runner.calls)


def test_absent_table_is_verified_absent_without_deletion():
    runner = Runner({"nftables": []})
    transport = NftablesTransport(runner)
    assert transport.verify(request(), scope()) == RuleState.ABSENT
    transport.remove(request(), scope())
    assert all(options["input"] is None for _, options in runner.calls)


def test_runtime_checks_interface_addresses_and_management_allowlist(monkeypatch):
    from ddos_detector import firewall_nft
    monkeypatch.setattr(firewall_nft.platform, "system", lambda: "Linux")

    def runtime(argv, **kwargs):
        if "address" in argv:
            result = [{"ifname": "enp0s8", "flags": ["UP"], "addr_info": [
                {"family": "inet", "local": "10.10.10.10"}]},
                {"ifname": "enp0s3", "addr_info": [{"family": "inet", "local": "10.0.2.15"}]}]
        else:
            result = [{"gateway": "10.0.2.2"}]
        return SimpleNamespace(stdout=json.dumps(result))

    validate_lab_runtime(scope(), runner=runtime)
    incomplete = FirewallScope("enp0s8", "10.10.10.10", ("127.0.0.0/8",), True)
    with pytest.raises(ValueError, match="Allowlist omits"):
        validate_lab_runtime(incomplete, runner=runtime)


def test_cleanup_empty_table_deletes_only_owned_table_and_confirms_absence():
    runner = Runner(owned_ruleset())

    def deleting_runner(argv, **kwargs):
        result = runner(argv, **kwargs)
        if kwargs.get("input"):
            assert json.loads(kwargs["input"]) == {"nftables": [
                {"delete": {"table": {"family": "ip", "name": "ml_ddos_lab"}}}]}
            runner.document = {"nftables": []}
        return result

    NftablesTransport(deleting_runner).cleanup_empty_table()
    assert runner.document == {"nftables": []}
    assert runner.calls[-1][1]["input"] is None


def test_cleanup_refuses_nonempty_table():
    runner = Runner({"nftables": []})
    transport = NftablesTransport(runner)
    runner.document = owned_ruleset({**transport._rule(request(), scope()), "handle": 7})
    with pytest.raises(ValueError, match="containing rules"):
        transport.cleanup_empty_table()
    assert all(options["input"] is None for _, options in runner.calls)


def test_cleanup_does_not_claim_success_if_table_remains():
    runner = Runner(owned_ruleset())
    with pytest.raises(RuntimeError, match="could not be confirmed"):
        NftablesTransport(runner).cleanup_empty_table()
