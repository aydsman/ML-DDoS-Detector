# Traffic generation and mitigation

Author: Mujtaba. Prepared November 19, 2026 for report section 7 and the
experimental-method appendices. This section describes implemented components
and separates reported lab observations from pending end-to-end evaluation.

## Legitimate workload

The HTTP client sends GET requests to the local test service or the isolated
protected server. A paced workload uses a fixed monotonic schedule, a configured
request-start duration, and a bounded number of simultaneous requests. A slow
response can finish after the scheduling interval. Missed slots are counted
rather than replayed as a burst. The configured rate describes intended request
starts, while the achieved rate uses completed attempts and actual elapsed time.

Each attempt records its run UUID, index, UTC and epoch start time, elapsed
milliseconds, outcome, status code and error class. JSON holds settings and
summary counters; CSV holds individual attempts. Finalization rebuilds CSV from
completed records so interrupted exports agree with the JSON summary. The slot
ledger distinguishes attempts, lag, capacity/deadline skips and cancellation.
An interrupted or incomplete trial is retained with its actual status.

The initial success predicate is an HTTP 2xx response. It does not verify page
content, a total request deadline, or detector effectiveness. HTTPX timeouts are
per operation. Skipped requests are not failed server responses. The source and
clock evidence needed for cross-host metrics must be supplied by the experiment
record. Implementation: `ddos_detector/http_client.py`; definitions and mapping:
[HTTP guide](../http-client.md) and [measurement formats](../measurement-formats.md).
PR #7 is merged; older lab reports retain their original component revisions.

## Controlled SYN and UDP workloads

The scenario generator constructs bounded IPv4 SYN or UDP packets for the
isolated server `10.10.10.10`, using the attacker VM's actual `10.10.10.30`
address. It requires the direct lab route and expected interface before sending.
Preview mode computes settings and packet budget without transmitting traffic.
Live sending requires an explicit execution option on the Linux attacker VM.
Limits are 1,000 packets/s, 60 seconds and 10,000 scheduled packets per run;
these are implementation limits, not validated attack-detection thresholds.

Exports preserve intended settings, actual send attempts/outcomes, timestamps,
stop reason and slot accounting. A send attempt does not establish arrival at
the server; server capture evidence must be matched to each run. Setup errors
finish as failed rather than leaving a running record. Ctrl+C during ARP setup
propagates through Scapy using `chainCC=1`, records interruption and stops the
run. JSON/CSV consistency and stop behavior have regression coverage.
Implementation: `ddos_detector/scenarios.py`; procedure: [scenario guide](../scenarios.md).

[PR #16](https://github.com/aydsman/ML-DDoS-Detector/pull/16) is merged.
Vince reported the ARP-interruption retest at `069191c`; earlier normal scenario
runs cover their reported revisions. Ali's run-record/export-format acceptance
is still pending on the [W2 card](https://trello.com/c/0zxzMJOm).

## Firewall lifecycle

The adapter accepts an explicit source IPv4 address, action ID, reason and
duration. The nftables transport owns a dedicated `ip ml_ddos_lab` table with
an input filter chain at priority -10 and an accept policy. Drop rules match
the source, incoming `enp0s8` and protected destination `10.10.10.10`. Rule
identity and exact scope are checked before removal by handle. Cleanup changes
only owned objects. The current live implementation supports the fixed lab
topology; a different JSON address alone does not adapt it to another network.

An installation is confirmed only after rule verification. The first confirmed
installation starts the expiry clock, normally 300 seconds; retries do not renew
it. Pending and unknown actions reserve capacity, with a default cap of 20.
There is one reservation per source across protocols. Protected/allowlisted
addresses are rejected. A verified absence releases the reservation and retires
the action ID. A subsequent block needs a new ID.

SQLite records reservations before installation and removal intent before
deletion, alongside structured audit events. A lifetime lock allows one owner
per journal. Restart reconciliation retains original confirmation times and
deadlines. Polling checks active rules as well as pending/expired actions;
uncertain observations retain capacity and are excluded from the confirmed
block report. Cleanup verifies removal and can be repeated. A process crash
can leave a rule installed until the recovery process resumes; kernel-side
automatic expiry is not implemented.

Implementation: `ddos_detector/firewall*.py`; commands and recovery procedure:
[firewall adapter guide](../firewall-adapter.md).

## Evidence and limits

| Evidence | What it supports | Limit |
| --- | --- | --- |
| W1/W2 tests and merged PRs | Pacing, accounting, export and controlled-stop behavior | Software tests do not prove server receipt or service availability |
| Vince's [November 17 lab report](https://github.com/aydsman/ML-DDoS-Detector/pull/36#issuecomment-6958519180), `2895768` | Reported scoped rule, attacker blocking, legitimate HTTP/SSH reachability, expiry, cleanup, permission failure, interruption and crash recovery | One run per case, one source/block, Python 3.14.4 rather than the project target 3.12; collaborator-reported evidence |
| Ayden's `aa327a4` and regression tests | Active-rule polling and startup-interrupt fixes, after the reported lab run | Updated-head Linux retest and review remain pending |

The monitor currently classifies aggregate windows and the dashboard serves
monitor-only data. An aggregate attack score is not a per-source verdict.
W4 must connect owner-approved source-policy requests to the adapter, preserve
uncertainty and reset policy streaks after removal/mode changes. Rate/share
thresholds remain unset because the reported benign and attack rates overlap.
The committed allowlist remains unverified. Automatic policy-driven blocking
and final detection/availability improvements have not been demonstrated.

## Reproducible experiment handoff

Use the [W5 collection checklist](../mujtaba-experiment-handoff.md). Retain
scenario settings and exports, server captures, monitor/model identity,
firewall audit/configuration and reset evidence under one experiment ID.
Keep repeated trials and failures, with separate component run IDs. Review
exports with `tools.review_measurements`; do not substitute sender settings for
received packet counts. Raw data and runtime journals remain outside Git.

Results to add after Ali's reviewed experiment schedule: trial IDs and revision,
offered/received traffic, legitimate response outcomes/latencies, confirmed block
times, removal/reset evidence and relevant uncertainty. No numerical performance
claim is filled from a synthetic test or an incomplete run.
