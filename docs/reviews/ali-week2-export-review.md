# Week 2 QA evidence review

I verified the fixture delivery in [PR #25](https://github.com/aydsman/ML-DDoS-Detector/pull/25) and checked saved VM records for the [Week 2 card](https://trello.com/c/ZxwJF4Ei). The twelve-feature arithmetic and fixture ledger remain in [the fixture guide](../week2-feature-fixtures.md).

## Normal service with the monitor enabled

I matched all 92 member hashes in the [issue #48 archive](https://github.com/user-attachments/files/35224245/issue48-live-evidence-2026-11-21.zip) against its inventory. The three archived benign runs used the trained-model monitor. They provide observed normal-service measurements under that instrumentation.

| Run | HTTP 200 / attempts | p50 (ms) | p95 (ms) | Achieved requests/s | Recorded lag skips |
| --- | ---: | ---: | ---: | ---: | ---: |
| 01 | 205/205 | 2.17 | 3.65 | 2.53 | 192 |
| 02 | 113/113 | 2.27 | 4.18 | 1.59 | 235 |
| 03 | 100/100 | 2.28 | 3.85 | 2.00 | 150 |

Client CSV and JSON pairs link by UUID. Request indexes are unique and UTC and epoch start fields agree within 2 μs. Latency percentiles use linear interpolation over sorted successful elapsed times for each run. Achieved rate divides actual attempts by reported elapsed time. All three targets were 5 requests/s. The exports predate the scheduled and cancelled counters required by the current full measurement validator. VM allocation and service configuration evidence is needed to establish comparability with a dedicated baseline. Status 200 is the success criterion in these saved records.

## Generator records

I matched 12 S1/S2 generator records to the supplied capture summaries by run UUID. The attempted, sent, skipped and cancelled counts reconcile. S1 reports 55,558 matching packets across six runs, and S2 reports 56,043 across six runs. Their corrected start times agree with the supplied capture summaries using the recorded offsets. The original capture bytes and independent clock measurements would be needed to verify full packet receipt and timing against the source. The review uses the [lab handoff](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6840894695) and [reconciliation files](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6956336176).

The [machine-readable results](ali-week2-export-review.json) retain the run IDs, archive hashes, observed measurements and unavailable counters. Keep Week 2 open for comparable baseline conditions and independent source capture and timing verification.
