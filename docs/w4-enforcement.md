# W4 source policy and temporary enforcement

Owner: Mujtaba. Implementation prepared November 19, 2026, on
`feature/mujtaba-w4-enforcement`, building on W3 PR #36. This implements the
policy-to-firewall path; automatic lab acceptance remains pending validated
settings, owner review and an isolated-Linux run. Committed defaults remain
monitor-only, with null thresholds and an unverified allowlist.

## Data and decision path

The shared accumulator retains bounded source/protocol packet and known SYN-only
counts alongside the twelve aggregate features. Finalized `WindowRecord` objects
carry immutable `SourceCount` diagnostics. They never enter the model vector.
Unknown flags contribute packets but never invented SYN evidence. A source cap
marks the whole window unusable for policy, and complete attribution must account
for every selected packet in the window.

`SourcePolicy` consumes the same finalized record that supplied the aggregate
score. Only an explicitly scored attack window can qualify a source. The
source/protocol packet rate must strictly exceed its configured threshold, or a
TCP SYN-only rate must strictly exceed its configured SYN threshold. Its share
must also meet the configured minimum, using all selected inbound packets as the
denominator. Null rate thresholds disable their comparison; a null share means
no source qualifies. These implement the accepted design, not a new choice of
validated numeric thresholds.

Streaks are per source/protocol, normally three consecutive epoch-aligned
one-second windows. Benign, unscored, capped, empty, missing and nonqualifying
windows break the applicable streak. Duplicate/out-of-order input is rejected.
Capture failures and mode changes reset streaks; verified rule disappearance or
expiry resets that source. Automatic mode also rejects stale or future windows
using an owner-reviewed maximum window age.

Eligible candidates are ordered by descending source/protocol packet count,
numeric IPv4 and protocol for deterministic ties. Only one action is considered
per source per window. A reserved source is not reinstalled or renewed, including
when its state is unknown. Capacity includes all pending/unknown reservations;
at the cap, candidates remain alerts and no existing rule is evicted. Protected
server/client, management allowlist, loopback, multicast, unspecified and global
broadcast addresses cannot qualify.

`Enforcement` turns qualifying automatic candidates into explicit W3
`BlockRequest` objects. The adapter preserves the first confirmed deadline,
verified state, durable removal intent and retired IDs. A polling timer runs on
capture iterations, including idle timeouts and filtered/busy traffic, without
waiting for another scored window. Processing or subprocess stalls can delay a
poll; no hard realtime or kernel expiry guarantee is claimed. The capture
timeout is at most half a second; individual nft subprocesses have five-second
timeouts. On exit or ordinary failure, cleanup is attempted while the journal
and audit log are still open. A crash still requires W3 journal recovery.

## Monitor-only replay on Windows

Use an existing trusted project model compatible with this Python environment:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.mitigate --replay tests/fixtures/week2/synthetic-mixed-boundaries.pcap --model <trusted-model-directory> --config docs/policy-defaults.json --log results/w4-preview.jsonl
```

Create the parent output directory first and use a new log path each time. This
parses the saved fixture, scores aggregate windows and records policy decisions.
It never creates a firewall transport or journal in monitor-only mode. The
committed null thresholds produce no qualified candidates. Synthetic model
packages are allowed only for this offline/monitor-only exercise, not automatic
enforcement. The original `ddos_detector.monitor` command is unchanged by default.

## Automatic isolated-lab run

Ayden must review the source-policy implementation and approve settings based on
validation evidence; Vince verifies runtime addresses and reachability. Copy the
defaults into a controlled local file under `results/` and retain the review
reference. Automatic configuration requires all of:

- `mode: "automatic"`, with explicit `--execute` and a live `--interface`.
- A verified scope/allowlist matching W3's fixed `enp0s8` / `10.10.10.10` lab.
- `policy_review_ref`: the actual review/evidence reference, not an invented ID.
- A non-null minimum share and at least one reviewed protocol/SYN rate threshold.
  Unset protocols remain disabled.
- A positive reviewed `max_window_age_seconds`, limiting delayed-window actions.
- A trusted model package with `data_kind: "reviewed_packet_windows"`; a demo
  model is refused even with `--execute`.

No values for those missing settings are supplied here. The existing evidence
shows overlapping benign/attack rates and does not establish usable thresholds.
After approval, run on the isolated server:

```sh
sudo .venv/bin/python -m ddos_detector.mitigate \
  --interface enp0s8 --execute --model results/<approved-model> \
  --config results/firewall/approved-policy.json \
  --state results/firewall/state.sqlite --log results/w4-trial-01.jsonl \
  --duration <reviewed-trial-seconds>
```

Keep one owner of the journal; do not run the W3 CLI concurrently. A restart uses
the same state and scope, reconciles saved rules before receiving new candidates
and retains original deadlines. SIGTERM and Ctrl+C both attempt cleanup before the process exits. Stop new workload before switching modes or
resetting a trial. The library's `set_mode` resets streaks and stops new automatic requests
when returning to monitor-only. Existing reservations keep their original
deadlines and must continue polling through verified expiry. Explicit cleanup
and process shutdown still attempt removal. The CLI fixes its mode for each invocation.

Exit 0 means normal processing and verified cleanup without failed firewall
observations; 2 means failure/unresolved cleanup; 130 means interrupted with
cleanup attempted. Retain the journal and inspect its reserved actions after any
failure. Use the W3 recovery CLI with the original configuration/state before
starting another trial. Never reset by deleting the journal or flushing nft.

## Audit and dashboard boundary

The new JSONL audit contains a configuration snapshot/hash and model identity,
aggregate window/status records, per-window candidates, requested block IDs,
latest verified firewall state and shutdown results. Requests reference the
aggregate window; they are not confirmed installations. Confirmed blocks are
listed only when the latest observation is installed; unknown IDs remain
explicit with reserved capacity. Complete firewall observations are retained in
the SQLite journal. In-memory polling events are bounded for this runner.

This mixed enforcement audit is separate from the original monitor-only API
import format. The existing dashboard continues its monitor-only store; it does
not display this automatic runner's blocks or provide mode controls. Aadi/Ayden
must integrate the reviewed events/store contract before advertising that UI.
The W4 command itself supplies the capture → score → source policy → firewall
loop and cleanup; it does not claim dashboard control integration.

## Verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_enforcement.py tests/test_mitigate.py tests/test_monitor.py tests/test_firewall.py tests/test_firewall_cli.py -q
```

Tests include the three-window source-attribution example; known/unknown flags;
bounded source tracking; strict rate/share rules; gaps and failures; protected
addresses; numeric-IP priority; one action per IP across protocols; cap and
uncertainty; original expiry; restart cleanup; mode resets; audit failure;
end-to-end simulated capture/scoring/firewall; repeated trial reset; and startup
or capture Ctrl+C. Those tests do not demonstrate real packet blocking.

Lab acceptance must exercise the reviewed settings and actual model with both
SYN and UDP trials, legitimate HTTP and management reachability, expiry without
new packets, external rule disappearance, permission/removal failures,
interruption/crash recovery and repeated resets. Record exact revision, raw
evidence and all trial outcomes. Keep the W4 card in Review/testing once code is
submitted; mark Done only after review and the applicable lab evidence.

## Ayden's Week 4 readiness checkpoint, November 22

The Random Forest, scaled MLP and aggregate rate-rule comparison is merged in PR #44. On the accepted S2 validation rows both learned models classified 550 of 550 eligible windows correctly. The aggregate rate rule had four false positives. The model-comparison document retains the experiment and artifact identities.

The source policy and mode/lifecycle implementation is reviewed in this draft. Its 152 focused policy, firewall, model/API and monitor checks passed at 35613ba. The [readiness record](reviews/week4-policy-readiness-2026-11-22.json) adds an offline run through the actual policy CLI using the trusted trained model and the saved benign Run 03 capture from issue #48. It processed 46 windows and 204 selected packets, reproduced all 46 original scores, and wrote 46 monitor-only policy decisions with zero block requests. Source-count diagnostics accounted for every selected packet. The model and metadata hashes were preserved.

The model defaults, score gate, three-window streak, capacity and lifecycle can be reviewed now. Completion still needs the following evidence.

| Remaining input or result | Responsible role | Acceptance |
| --- | --- | --- |
| Complete S1/S2 source/protocol and known SYN-only counts aligned to reviewed labels and aggregate scores | Vince supplies, Ayden reviews | Reproducible policy evaluation with source-level errors, decisions and exclusions |
| Rate/SYN/share settings and maximum window age | Ayden with validation evidence | A recorded review of the full model-gated policy |
| Current interface, destination, allowlist and firewall state | Vince and Mujtaba | Verified runtime configuration and legitimate-client/management reachability |
| Policy-driven live lifecycle | Vince and Mujtaba, Ayden reviews | Recorded expiry, duplicate/cap, failure, cleanup and recovery outcomes on the accepted revision |

Dashboard consumption of the reviewed enforcement events remains shared work with Aadi. The current API exposes monitor-only data. The source-policy pilot is tracked separately from CIC issue #3.
