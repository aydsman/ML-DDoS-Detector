"""Explicit Linux nftables transport restricted to the isolated lab table."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
import json
import platform
import subprocess

from .firewall_contract import RuleState

TABLE = "ml_ddos_lab"
CHAIN = "inbound"
OWNER = "ml-ddos-detector-v1"


class NftablesTransport:
    def __init__(self, runner=subprocess.run):
        self.runner = runner

    def _run(self, arguments, commands=None):
        result = self.runner(["nft", "-j", *arguments],
                             input=None if commands is None else json.dumps({"nftables": commands}),
                             capture_output=True, text=True, timeout=5, check=False)
        if result.returncode:
            raise RuntimeError(f"nft failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout

    @staticmethod
    def _check_scope(request, scope):
        scope.check_source(request.source_ip)
        if scope.interface != "enp0s8" or scope.protected_ip != "10.10.10.10":
            raise ValueError("Live transport requires the verified enp0s8/10.10.10.10 lab scope")

    @staticmethod
    def _comment(request):
        return OWNER + ":" + hashlib.sha256(request.block_id.encode()).hexdigest()

    def _rule(self, request, scope):
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}

        return {"family": "ip", "table": TABLE, "chain": CHAIN,
                "comment": self._comment(request), "expr": [
                    match({"meta": {"key": "iifname"}}, scope.interface),
                    match({"payload": {"protocol": "ip", "field": "daddr"}}, scope.protected_ip),
                    match({"payload": {"protocol": "ip", "field": "saddr"}}, request.source_ip),
                    {"drop": None},
                ]}

    def _inspect(self):
        document = json.loads(self._run(["list", "ruleset"]))
        rows = document["nftables"]
        if not isinstance(rows, list):
            raise ValueError("Invalid nftables ruleset")
        tables = [row["table"] for row in rows if "table" in row
                  and row["table"].get("family") == "ip" and row["table"].get("name") == TABLE]
        owned = [row for row in rows if any(isinstance(obj, dict) and obj.get("family") == "ip"
                 and obj.get("table") == TABLE for obj in row.values())]
        if not tables:
            if owned:
                raise ValueError("Objects found without their owning table")
            return False, []
        if len(tables) != 1 or tables[0].get("comment") != OWNER or tables[0].get("flags"):
            raise ValueError("Existing lab table has unrecognized ownership or flags")
        chains = [row["chain"] for row in owned if "chain" in row]
        if len(chains) != 1:
            raise ValueError("Lab table must contain exactly one chain")
        chain = chains[0]
        expected = {"name": CHAIN, "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}
        if any(chain.get(key) != value for key, value in expected.items()):
            raise ValueError("Lab chain scope or policy changed")
        if any(set(row) - {"chain", "rule"} for row in owned):
            raise ValueError("Unexpected object in lab table")
        return True, [row["rule"] for row in owned if "rule" in row]

    def _matching(self, request, scope, rules):
        expected = self._rule(request, scope)
        matches = [rule for rule in rules if rule.get("comment") == expected["comment"]]
        if len(matches) > 1:
            raise ValueError("Duplicate rules for one block action")
        if matches and any(matches[0].get(key) != value for key, value in expected.items()):
            raise ValueError("Block rule differs from the exact requested scope")
        return matches

    def verify(self, request, scope):
        self._check_scope(request, scope)
        _, rules = self._inspect()
        return RuleState.INSTALLED if self._matching(request, scope, rules) else RuleState.ABSENT

    def apply(self, request, scope):
        self._check_scope(request, scope)
        exists, rules = self._inspect()
        if self._matching(request, scope, rules):
            return
        commands = []
        if not exists:
            commands.extend([
                {"create": {"table": {"family": "ip", "name": TABLE, "comment": OWNER}}},
                {"add": {"chain": {"family": "ip", "table": TABLE, "name": CHAIN,
                                   "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}}},
            ])
        commands.append({"add": {"rule": self._rule(request, scope)}})
        self._run(["-f", "-"], commands)

    def remove(self, request, scope):
        self._check_scope(request, scope)
        _, rules = self._inspect()
        matches = self._matching(request, scope, rules)
        if matches:
            handle = matches[0].get("handle")
            if type(handle) is not int or handle < 1:
                raise ValueError("Missing or invalid rule handle")
            self._run(["-f", "-"], [{"delete": {"rule": {
                "family": "ip", "table": TABLE, "chain": CHAIN, "handle": handle}}}])

    def check_inventory(self, requests, scope):
        """Reject orphan/foreign rules before any new installation."""
        _, rules = self._inspect()
        expected = {self._comment(request): request for request in requests}
        for rule in rules:
            request = expected.get(rule.get("comment"))
            if request is None:
                raise ValueError("Lab table contains a rule absent from the journal; manual reconciliation required")
            self._check_scope(request, scope)
            self._matching(request, scope, rules)

    def cleanup_empty_table(self):
        """Reset only our empty table after all journal actions are absent."""
        exists, rules = self._inspect()
        if rules:
            raise ValueError("Cannot reset a lab table containing rules")
        if exists:
            self._run(["-f", "-"], [{"delete": {"table": {"family": "ip", "name": TABLE}}}])
            if self._inspect()[0]:
                raise RuntimeError("Lab table removal could not be confirmed")


def validate_lab_runtime(scope, runner=subprocess.run):
    """Read runtime addresses/routes and reject an incomplete management allowlist."""
    if platform.system() != "Linux":
        raise ValueError("Live firewall commands require the isolated Linux server")
    if not scope.verified or scope.interface != "enp0s8" or scope.protected_ip != "10.10.10.10":
        raise ValueError("A verified lab interface, destination and allowlist are required")
    networks = [IPv4Network(entry) for entry in scope.allowlist]

    def covered(value):
        return any(IPv4Address(value) in network for network in networks)

    def read(arguments):
        result = runner(["ip", "-j", *arguments], capture_output=True, text=True, timeout=5, check=True)
        return json.loads(result.stdout)

    interfaces = read(["address", "show"])
    lab = [row for row in interfaces if row["ifname"] == scope.interface]
    if len(lab) != 1 or "UP" not in lab[0].get("flags", []):
        raise ValueError("Lab interface is missing or down")
    if not any(addr.get("local") == scope.protected_ip for addr in lab[0]["addr_info"]):
        raise ValueError("Protected destination is not configured on the lab interface")
    required = ["10.10.10.10", "10.10.10.20", "127.0.0.1"]
    required.extend(addr["local"] for row in interfaces for addr in row.get("addr_info", [])
                    if addr.get("family") == "inet")
    required.extend(row["gateway"] for row in read(["route", "show"]) if "gateway" in row)
    if not all(covered(address) for address in required):
        raise ValueError("Allowlist omits protected, local or gateway addresses")
    if covered("10.10.10.30"):
        raise ValueError("Attacker address must not be allowlisted")
