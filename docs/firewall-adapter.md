# Firewall adapter and explicit lab requests

Owner: Mujtaba. PR #36 implements apply, verification, expiry polling, removal,
SQLite state/audit storage, restart reconciliation and cleanup. The Linux
transport uses a dedicated nftables table. Automated tests use simulated
transports and command output. Vince reported manual isolated-Linux checks on
November 17 at commit `2895768`, including rule scope, legitimate HTTP and
management reachability, expiry, and interrupt/restart cleanup. See the
[lab report](https://github.com/aydsman/ML-DDoS-Detector/pull/36#issuecomment-6958519180).
That run covered a single block on the project's fixed lab interface and
addresses. The later periodic verification change is covered by offline tests.

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
default, rechecking confirmed rules, uncertain installations and pending
removals. A confirmed rule that disappears releases its reservation when
the adapter verifies absence. The state
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

The live transport is intentionally fixed to this three-VM lab: `enp0s8`,
server `10.10.10.10`, legitimate client `10.10.10.20` and attacker `10.10.10.30`.
Changing just `protected_ip` in JSON does not support a different topology;
the runtime and source protections must be reviewed together for that change.

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

### Updated-head external-removal check

Ayden's `aa327a4` rechecks active rules on each poll and includes startup
reconciliation in interrupt cleanup. The November 17 lab report predates that
change. Run this from a Git checkout on the isolated server after checking out the exact
PR head, with the owner-verified local configuration and no other firewall
worker or experiment running:

```sh
sudo .venv/bin/python -m tools.check_firewall_poll --execute \
  --config results/firewall/lab-config.json \
  --output results/firewall/poll-retest-01
```

Use a new output directory for every attempt. The check creates a fresh journal,
rejects unexpected existing rules, installs one 300-second block for the lab
attacker, then removes that exact rule directly through the transport. It calls
the regular expiry poll before the deadline and requires the confirmed block
and reservation to disappear. It also checks that the retired ID cannot be
reused and that empty-table cleanup works twice. No packets are generated and
no global ruleset is flushed. Keep legitimate HTTP and management SSH open for
the separate reachability check; this command does not measure either.

Retain `check.json`, `config.json`, `state.sqlite` and `state.sqlite.lock`
outside Git. The report includes the tested commit, dirty status, Python/OS,
configuration hash, raw nft/ip command responses and before/after observations.
Exit 0 means these checks passed; 2 means failure; 130 means interrupted.
If cleanup fails, preserve the journal and use the existing recovery CLI with
that directory's `config.json` and `--state <directory>/state.sqlite`.
A killed process can leave `status: running`; that record is incomplete.
The test's own cleanup is attempted on an ordinary exception or Ctrl+C.

Vince approved the tested head `3de3ce6` on November 20, 2026. His report
records successful external removal, retirement and repeated cleanup
(`check.json` SHA-256 `805d90d421e65486f9b9ddc33ee0ab1e984e7a46bc3f11a57578b91f354411ca`).
A separate 90-second block stopped attacker HTTP until expiry while legitimate
HTTP and management SSH remained reachable. These are collaborator-reported
lab observations, not independently replayed raw artifacts. The November 17
scope/crash checks were at `2895768` and were not repeated on this head.
See [the exact-head review](https://github.com/aydsman/ML-DDoS-Detector/pull/36).
PR #36 is merged into development; W4 automatic-policy trials remain separate.
Offline tests do not replace lab acceptance.

## W4 handoff

The [W4 enforcement runner](w4-enforcement.md) now connects finalized-window
source diagnostics and the accepted policy design to this adapter. Its default
is monitor-only; approved thresholds, reviewed source-policy behavior and runtime
scope are still required for automatic lab acceptance. The original monitor/API
flow below continues to operate independently.

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
