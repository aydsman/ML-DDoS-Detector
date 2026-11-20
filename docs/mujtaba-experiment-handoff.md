# W4 and W5 enforcement and experiment handoff

Owner: Mujtaba. November 19, 2026.

## Current sequence

1. Finish PR #36 updated-head lab verification with Vince and reviewer acceptance.
   The adapter is implemented; W3 stays In progress until acceptance and merge.
2. Review and validate the [implemented W4 source-policy/enforcement runner](w4-enforcement.md)
   with Ayden and Vince. The November 18 planning deadline has passed; owner
   review and validated settings remain required before automatic lab acceptance.
3. Collect W5 experiments using Ali's agreed schedule and frozen configuration;
   the planning deadline is November 25. The report contribution is prepared in
   [traffic and mitigation](contributions/mujtaba-traffic-mitigation.md).

## W4 integration boundary

| Producer or lifecycle event | Required integration behavior |
| --- | --- |
| Aggregate model alert | Never turn the aggregate alert alone into a `BlockRequest` |
| Qualified source-policy request | Ayden supplies source/protocol evidence, aggregate reference, configured thresholds/share and three consecutive valid windows; only automatic mode requests enforcement |
| Candidate ordering | Descending source/protocol packet count, then numeric IPv4; deduplicate to one reservation per IP across protocols |
| Repeated candidate while reserved | Reuse the same action identity; do not renew confirmation or expiry |
| Apply result | Publish a confirmed block only for latest verified installed state, using original `blocked_at`/`expires_at`; retain unknown reservations |
| Periodic timer, even with no packets | Call `expire_due()`; packet arrival must not be the expiry timer |
| Missing/failed/empty/nonqualifying window or mode change | Reset relevant policy streaks; never replace unavailable data with qualifying evidence |
| Verified absence/expiry | Release capacity, notify policy to reset the source streak, and use a fresh ID for a later action |
| Shutdown/reset | Stop accepting new requests, call verified cleanup, retain unresolved journal entries, and remove the owned table only after verified absence |

`FirewallAdapter` enforces scope, cap, duplicate reservations, original deadlines
and durable cleanup. The W4 `SourcePolicy`/`Enforcement` implementation now owns
eligibility, ordering and streak resets using finalized `WindowRecord.source_counts`.
It needs Ayden's review against the accepted design and validated settings. The
separate `mitigate` runner connects capture, scoring, policy and firewall. The
current API store still accepts monitor-only events and serves an empty block
list; dashboard controls/store integration remain with Aadi/Ayden. Do not invent
sources or fill null thresholds.

The manual lab helper in [the adapter guide](firewall-adapter.md#updated-head-external-removal-check)
checks the latest polling fix. It does not substitute for policy-driven trials.

## Before each experiment

- Confirm Ali's trial order, repetitions, legitimate workload, attack settings,
  observation/recovery intervals and success predicate. Record the review reference.
- Copy [the run-record template](templates/run-record.template.json) into a new
  experiment directory under `results/`. Fill its real run ID, condition,
  comparison/trial IDs, source/clock identities, code revision/dirty state and
  environment. Leave unavailable fields null with a reason.
- Preserve the frozen configuration, dependency versions, model identity/hashes,
  capture filters, resource record and the separately reviewed runtime allowlist.
- Stop the previous firewall owner. Use the original journal and configuration to
  clean up; keep its output and command exit code. Confirm the owned table is
  absent and preserve the entire before/after ruleset for comparison. Other
  existing firewall rules must remain unchanged. An unresolved reservation is a
  failed reset, not permission to discard the journal and start again.
- Record successful legitimate HTTP and management connectivity before traffic.
  Start capture/resource/monitor logging over the agreed observation bounds.

## During and after a trial

Use the existing HTTP and scenario commands in [the HTTP guide](http-client.md)
and [scenario guide](scenarios.md), with Ali's reviewed settings. Preserve their
separate UUID folders and map them to the parent experiment ID. Keep the first
trial, failed trials and interrupted attempts. Do not cherry-pick a successful run.

Validate the actual component export folders, for example:

```sh
.venv/bin/python -m tools.review_measurements \
  results/<http-component-run> results/<scenario-component-run> \
  --experiment-id <parent-experiment-id> \
  --output results/<parent-experiment-id>/export-review.json
```

Replace placeholders with real retained paths/IDs. Review output validates
exports; it does not verify arrival, capture completeness or clock alignment.

Retain these artifacts in the run record's existing `artifacts` array with
actual SHA-256 hashes, byte sizes and paths using the measurement schema:

| Artifact | Record |
| --- | --- |
| HTTP JSON/CSV and validation output | Settings, attempts, outcomes, slot ledger, client UUID |
| SYN/UDP JSON/CSV and validation output | Settings, send attempts, stop reason, scenario UUID |
| Server PCAP and capture-health output | Received traffic, capture bounds, filters, drops, source identity |
| Monitor audit and model/config snapshots | Aggregate scores, missing/failed windows, model and thresholds |
| Firewall journal/audit, CLI output and rulesets | Requests versus confirmed blocks, uncertainty, original deadlines and removal |
| Resource/service/clock records | VM allocations, actual runtime versions, background load, clock uncertainty |
| Cleanup output and post-trial HTTP/SSH check | Verified reset, no unresolved reservations and connectivity recovery |

Observe recovery over Ali's agreed interval. Stop workload processes, save all
terminal exports, run verified firewall cleanup and repeat it to check a no-op.
Save the exit codes and actual ruleset comparison; an empty final CLI `blocks`
list alone does not establish an empty kernel ruleset. If the process crashed,
recover using its original state/configuration before starting another trial.

Do not run the automatic comparison condition until Ayden has approved the
policy/settings and Vince has verified runtime scope. Record a blocked condition
with its reason instead of labelling monitor-only traffic as ML mitigation.

## Acceptance still needed

- Vince: updated-head PR #36 external-disappearance check and reachability, with
  evidence path and tested commit; requested review before merge.
- Ali: W2 scenario export-format acceptance and W5 schedule/configuration.
- Ayden: review the implemented source policy/settings and dashboard integration.
- Mujtaba: resolve review findings, exercise the implemented lifecycle across
  repeated lab trials, preserve records and update the contribution with verified results.
- Aadi: incorporate the prepared prose into the final report with evidence links.

This checklist and contribution are prepared work. No experiment is marked run,
no reviewer acceptance is assumed, and no card is marked Done by these files.
