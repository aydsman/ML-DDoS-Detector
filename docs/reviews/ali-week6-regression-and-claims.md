# Week 6 regression and numerical claims audit

Candidate `a2ea4668682094390a02892ce5134b3844f35521` is the current development snapshot tested on November 26. The final submission build and assembled report are still pending. [Week 6 card](https://trello.com/c/QzxEu5FL).

## Candidate regression

| Check | Result | Scope |
| --- | --- | --- |
| Python 3.12.15 and macOS | 587 passed, seven skipped, one dependency deprecation warning | Full suite, including the local HTTP server test. Two saved lab capture parametrizations, one lab frame check and four tshark-dependent cases were unavailable. |
| Node v24.11.1 | 39 passed | All five frontend test files, covering API contract, recorded and stale states, graph gaps and polling. |
| Python dependencies | No broken requirements | pip check in the project virtual environment. |

From the candidate checkout, run `python -m pytest -q -rs -p no:cacheprovider`, `node --test tests/frontend-*.mjs` and `python -m pip check`. The HTTP test needs loopback socket access. The initial sandboxed invocation denied that bind. A full rerun with loopback access passed.

The [saved regression record](ali-week6-regression.json) lists the exact skipped cases.

## Numerical claim register

| Claim | Trace and support |
| --- | --- |
| S1/S2/S3 retained attack/benign counts of 253/300, 250/300 and 300/300 | Reproduced from the three original [candidate window exports](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6840894695) with the timestamp-ordered binary class cap. [Baseline report](../week2-pilot-baseline.md). |
| 550 S2 windows, RF and MLP at F1 1.0 | Counts reconcile to 300 benign plus 250 attack with zero reported errors. Model outputs are attributed to the [owner comparison](../model-comparison.md). |
| Rate rule F1 0.9921 and false-positive rate 1.33% | Recalculated from 250 TP, 296 TN, four FP and zero FN in the [comparison](../model-comparison.md). |
| 21.807/38.519 ms RF and 1.162/2.195 ms MLP median/p95 | [Timing summary](inference-benchmark-2026-11-21.json) reports 2,750 calls per model. Per-round call sums, weighted means and extrema reconcile. Raw per-call files are needed to recompute percentiles. These are laptop prediction times. |
| 418 HTTP 200 responses, 173 scored windows and zero alerts | Recounted from the [issue #48 archive](https://github.com/aydsman/ML-DDoS-Detector/issues/48). These were three benign monitored runs with incomplete workload pacing and unknown monitor kernel drops. [Owner source review](issue48-live-acceptance-2026-11-22.json). |
| CIC 479 windows, eight candidate positives, 471 excluded | Historical v1 candidate count and manifest reconciliation. CIC labels and train/test split require the [source handoff](https://github.com/aydsman/ML-DDoS-Detector/issues/3). |
| Incident delay, protection benefit, service recovery, held-out accuracy | Pending approved policy, matched full-system logs and held-out release. |

For the demo, the frontend tests exercise current, recorded, stale and unavailable states. The saved benign lab acceptance includes advancing API results and capture startup failure. Active block and expiry with measured client recovery require the integrated Linux acceptance.

## Final handoff

- Run the checks above on the final candidate and retain the full commit ID, runtime and skipped cases.
- Reconcile sections 9 and 10 with the [evaluation figure and its source data](https://github.com/aydsman/ML-DDoS-Detector/pull/59). Preserve the label on the benign monitor runs and the achieved request rate in every reuse of the chart.
- In the infrastructure section, reconcile the packet-count discrepancy identified in [PR #53](https://github.com/aydsman/ML-DDoS-Detector/pull/53) with the dated [rebuild record](https://github.com/aydsman/ML-DDoS-Detector/issues/49#issuecomment-7206990025).
- Match any final classifier numbers to the reviewed release output from [PR #52](https://github.com/aydsman/ML-DDoS-Detector/pull/52). The existing S2 numbers are validation results.
- Confirm the Linux demo behavior from the completed [monitor retest](https://github.com/aydsman/ML-DDoS-Detector/pull/41) and [policy acceptance](https://github.com/aydsman/ML-DDoS-Detector/issues/51). Use the saved benign monitor evidence for claims at that scope until these are available.
