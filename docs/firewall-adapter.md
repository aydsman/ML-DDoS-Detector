# Firewall adapter and explicit lab requests

Owner: Mujtaba. PR #36 implements apply, verification, expiry polling, removal,
SQLite state/audit storage, restart reconciliation and cleanup. The Linux
transport uses a dedicated nftables table. Automated tests use simulated
transports and command output. Real kernel rule parsing, packet blocking,
management reachability and restart cleanup require Vince's isolated-lab
verification before W3 acceptance. The interface remains under owner review.

## Requests and results

`BlockRequest(block_id, source_ip, reason, duration_seconds=300)` identifies one
action across retries. `FirewallResult` records the operation, success, observed
rule state (`installed`, `absent`, `unknown`), observation time and error detail.
`confirmed_blocks` preserves the first confirmation time and its expiry time.
`firewall_cli.report()` maps these to the API block fields, with UTC timestamps.

Unknown install/removal outcomes retain a capacity reservation. Retries observe
the same action before proceeding. A confirmed action's ID is retired after
verified absence, so a later block needs a fresh ID. The default capacity is 20.
SQLite writes the reservation before installation and stores removal intent
before deletion. A failed journal write stops further actions. One state owner
holds an exclusive database lock for its lifetime. After restart, reconciliation
observes saved actions and preserves original confirmation/expiry timestamps.
An expired rule or failed removal remains reserved until absence is confirmed.

The runtime must call `expire_due()` regularly. The CLI polls every second by
default, including uncertain installations and pending removals. The state
database and its `.lock` file must be retained together in controlled local
storage. Losing the journal requires manual reconciliation of the lab table.
An unexpected owned-table rule aborts startup. Keep all generated state outside
Git under `results/`. Audit events are transactionally recorded in the same
database's `audit` table and can be read using `FirewallState.events()`.

## Linux transport scope

Vince's latest reported firewall inspection is recorded in
[policy-proposal.md](policy-proposal.md). It reports UFW inactive, an empty nft
ruleset, and ACCEPT-only iptables policies. Actual runtime verification remains
required for every lab session.

The transport owns only table `ip ml_ddos_lab`, identified by an ownership
comment, with an INPUT filter chain at priority -10 and ACCEPT policy. Each drop
rule matches the request's IPv4 source, incoming `enp0s8`, and destination
`10.10.10.10`. Block IDs become SHA-256 rule comments. Verification compares the
exact rule expression and identity. Removal uses that verified rule's handle.
Cleanup deletes the owned table only after all actions and rules are confirmed
absent. Foreign tables, SSH rules, existing policies and UFW configuration stay
under their existing owners.

Subprocess commands use argument lists and JSON input, with a five-second
timeout. A failed command or unreadable ruleset produces an unknown observation.
Runtime checks require Linux, the configured destination on an UP lab NIC, and
allowlist coverage of the server, legitimate client, local IPv4 addresses and
gateways. The attacker address must remain outside the allowlist.

## Lab verification procedure

Ayden and Vince must review the interface and verify the actual firewall,
interface, destination, management addresses and allowlist first. Preserve the
raw command output as lab evidence. Use snapshots and a local console during
the first firewall test. The committed policy defaults retain
`allowlist.verified=false`, `monitor_only`, and unset policy thresholds. An
approved local configuration under `results/` supplies the verified lab values.

Create `results/firewall/requests.json` with an explicit manual request:

```json
[{"block_id":"manual-lab-001","source_ip":"10.10.10.30","reason":"Manual lab verification","duration_seconds":300}]
```

On the isolated Linux server, using its project environment:

```sh
sudo .venv/bin/python -m ddos_detector.firewall_cli apply --execute --config results/firewall/lab-config.json --requests results/firewall/requests.json
```

The command owns the journal, applies explicit requests, polls to verified
expiry/removal and then prints its final block report. Ctrl+C requests verified
cleanup and exits 130, retaining unresolved actions in the journal. After a
crash, resume polling with the same state and configuration:

```sh
sudo .venv/bin/python -m ddos_detector.firewall_cli reconcile --execute --config results/firewall/lab-config.json
```

For experiment reset:

```sh
sudo .venv/bin/python -m ddos_detector.firewall_cli cleanup --execute --config results/firewall/lab-config.json
```

`status --execute` reconciles and reports the journal's actions once. A second
process cannot open the same state while the first owns it. Stop the current
owner before running a maintenance command. SQLite state-path changes or
configuration changes must be reconciled explicitly with the original scope.
The report includes the session's structured events. If the last observation
is uncertain, the action is listed in `uncertain_block_ids` and still reserves
capacity. It appears in `blocks` when its latest observation confirms
installation, with the original confirmation and expiry timestamps.
Exit 2 indicates any failed
or uncertain observation during the session, even if a later reconciliation
resolves it. Exit 130 indicates operator interruption. After a process crash,
rules can remain until this polling process is restarted and confirms cleanup;
lab acceptance must exercise that recovery procedure.

Vince should record rule listings, actual blocked attacker traffic, successful
legitimate HTTP/management traffic, timed expiry, repeated cleanup, permission
failure, interruption and process-restart recovery. Match every artifact to the
tested commit and request ID. Earlier generator results cover their reported
revisions only.

## W4 handoff

The adapter accepts explicit `BlockRequest` objects. The existing monitor and
dashboard continue their monitor-only flow. W4 policy integration needs actual
per-source evidence, validated thresholds and owner-approved eligibility before
calling `apply`. It must use numeric-IP tie breaking, reset streaks after
confirmed removal/mode changes and publish blocks only from verified state.
No threshold is inferred from the manual lab test. The configuration's null
thresholds and unverified allowlist remain gates for automatic enforcement.

## Offline checks

```sh
python -m pytest tests/test_firewall.py tests/test_firewall_contract.py tests/test_firewall_recovery.py tests/test_firewall_nft.py tests/test_firewall_cli.py -v
```

The cases cover validation, retries, capacity, expiry/removal, concurrent calls,
write-ahead crash recovery, original deadlines, journal failure, single-owner
locking, rule identity/scoping, orphan rejection and the explicit CLI gates.
The nft command format follows the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).
