# Week 3 monitor QA evidence

The [Week 3 card](https://trello.com/c/ONn45Kyr) calls for benign, incident and mixed traffic with independent labels. I reviewed the benign monitor runs captured at `f99ca6b` under [issue #48](https://github.com/aydsman/ML-DDoS-Detector/issues/48). All 92 evidence member hashes match. The logs completed and each emitted one-second window was scored. Window timestamps are in order without duplicates, and the stored decisions agree with their scores and threshold.

| Run | Scored windows | Inbound packets | Alert windows | Post-window delay p95 (s) | Post-window delay max (s) | Unrepresented seconds between first and last windows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 01 | 70 | 418 | 0 | 1.439 | 1.496 | 12 |
| 02 | 57 | 230 | 0 | 1.432 | 1.470 | 15 |
| 03 | 46 | 204 | 0 | 1.442 | 1.479 | 5 |

The delay measures recorded processing time after window close. Incident-onset delay requires a separately timed incident and matching alert. Unrepresented seconds have no recorded window. The monitor recorded zero late drops and left kernel drops and backlog unknown.

For run 03 I independently parsed the saved Ethernet capture. Its 308 frames include 204 in-scope packets. Counts match all 46 scored windows, and IP byte totals match all 34 distinct windows present in the saved API metric snapshots. Run 02 has four successive advancing snapshots and run 03 has three. The startup failure log records capture unavailable. The [owner review](issue48-live-acceptance-2026-11-22.json) separately records a model-score reproduction.

See the [recomputed evidence](ali-week3-monitor-review.json). A paired incident/mixed monitor audit and independently aligned source labels are still needed to measure missed events, detection delay and overhead. The S1/S2 training-data capture summaries supply workload context. Those sessions lack the paired monitor audit for those metrics.
