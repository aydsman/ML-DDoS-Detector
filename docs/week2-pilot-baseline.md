# Week 2 controlled-lab Random Forest baseline

The November 18 baseline uses reviewed packet windows from three controlled-lab
sessions. The [dataset review](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6987025978)
records which portions of the evidence could be reproduced from the packet
exports and which depend on the capture owner's records. The CIC-DDoS2019
candidate review is separate.

| Split | Session | Benign | SYN label | UDP label | Excluded by label rules |
| --- | --- | ---: | ---: | ---: | ---: |
| Training | S1 | 300 | 163 | 90 | 151 |
| Validation | S2 | 300 | 162 | 88 | 153 |
| Held-out test | S3 | 300 | 162 | 138 | 91 |

Select the first 300 eligible windows per binary class in timestamp order,
keeping any smaller class as supplied. The selection cap set aside another
227, 228 and 228 benign windows and 0, 0 and 12 attack windows respectively.
The input preserves all label exclusions for audit. The stale HTTP record
from S3's failed first attempt is outside the successful capture interval.

The baseline used 100 trees, seed 3670, class balancing fitted on S1 only,
no scaling or imputation, and the provisional 0.5 decision threshold.
On the 550 eligible S2 windows it produced 300 true negatives and 250 true
positives, with zero false positives or false negatives. Save/reload
verification passed, and an explicit score of a saved S2 benign feature
record returned the same model identity and a benign prediction.

S3 remains unscored for final evaluation. The S2 result describes this
single lab's eligible windows. The workload is narrow, resets from the same
source contribute to the SYN labels, and mixed windows below the labeling
threshold are excluded. The result establishes a baseline for these inputs.
Broader coverage and model performance on other traffic conditions remain
unverified.

## Reproduction record

Training code revision: `d53fe7b`. Use the training CLI in
[training.md](training.md) with the reviewed records and manifest, 100 trees,
seed 3670, and threshold 0.5. Keep the saved model and all data files outside
Git. The package records the dependency versions, settings and feature order.

| Local artifact | SHA-256 |
| --- | --- |
| reviewed-windows.json | abfb8270d4120cda5aaf7d41245e8efaa8078c7c599ae1da674994ac0cb54519 |
| reviewed-splits.json | fd42c0d424a3fc61d51bec9c1f03b56f313c4021036bdaad8de7c8453dbefc05 |
| model.joblib | 44f2ae879b63414c8af7d7c1165e7a0d462c9545f6190f7a8a7b2f00aa9e9fe7 |

The trained-model benign live monitor/API run is now independently reviewed in
[the monitor acceptance record](monitor.md#trained-model-live-acceptance-reviewed-november-22).
The owner reproduced 46 packet-derived scores and matched the supplied API
snapshots. This completes the live integration check, not attack accuracy,
automatic enforcement or held-out S3 evaluation.

## November 20 metadata correction

The [supplied correction archive](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-7048760662)
was independently checked against the original lab-handoff and reconciliation
archives. Its SHA-256 is
`44cf9ae6fba60473a587149c9590a8c57e77f0e38c243fce3fefc087739ae2f6`.
Both supplied before files match the corresponding original archive members
byte for byte; all four metadata-file checksums match the supplied inventory.
The [machine-readable review](reviews/lab-pilot-correction-2026-11-20.json)
records those identities and limits.

Only `excluded_runs` and `status_note` changed in the S3 source manifest. They
explicitly exclude the stale failed-attempt HTTP run
`aab41db8-1313-44f9-81ea-0a84063c0d7c` and zero-sent orphan SYN run
`39903db2-4acc-467e-86dc-2299da9fcf2a`, retaining their original provenance
references. The corrected manifest SHA-256 is
`eb7f24d2fe59a2eeb28f077d31169ed9fc06c7817af3a3d64206887f9bb2451d`;
the preceding source version was
`54d09051c5eedd6543ce35638142e566aecfdfae631f89f392d71f332ad15ecc`.
These source-manifest identities differ from the reviewed-splits hash above.
The source manifest still identifies an unreviewed candidate with unassigned
splits and null review references; the separate owner-approved pilot inputs
remain the frozen reviewed package.

The reconciliation README changes only `slack 1.0 s` to `slack 2.5 s`, matching
`slack_seconds` in all three original session coverage files. Its corrected
SHA-256 is `2bfab08ede7aad6fc5cd74a124f8bed6a1db2500a963d93752479d823497a06a`;
the original is
`06ae8af7c98d53899ea1c9bdadb4b34d5d638a8c6a24f5696c943979bbe35b00`.

This metadata correction is accepted. The correction supplies no new windows,
coverage, captures or labels. Hash checks confirm the existing frozen reviewed
inputs and model are unchanged. No retraining, resplitting or final-test scoring
was performed. Source PCAP bytes were not rehashed or replayed, and the separate
CIC acceptance issue and Linux trained-model acceptance remain open.
