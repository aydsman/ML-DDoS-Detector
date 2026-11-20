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

Week 3 verification still needs a monitor-only lab run with these saved model
bytes and confirmation that the timestamped predictions appear through the
API. The previously recorded monitor run used the synthetic demo model.

## November 20 metadata correction

[Vince reported](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-7046858680)
that his local reconciliation README now states the actual 2.5-second boundary
slack, and his S3 source manifest explicitly excludes the stale failed-attempt
HTTP run `aab41db8-1313-44f9-81ea-0a84063c0d7c` and zero-sent orphan SYN run
`39903db2-4acc-467e-86dc-2299da9fcf2a`. He reports windows/coverage unchanged
and no recomputed labels. The corrected source-manifest SHA-256 is
`eb7f24d2fe59a2eeb28f077d31169ed9fc06c7817af3a3d64206887f9bb2451d`;
the preceding source version was
`54d09051c5eedd6543ce35638142e566aecfdfae631f89f392d71f332ad15ecc`.
These are source-manifest identities, not the reviewed-splits hash above.

The corrected files have not yet been supplied here. Retain the originally
reviewed reconciliation archive
`691e9887215e0a2f7451ff547739ca813b9b15a4a640de8b3d866e99f9916651`
and the frozen training inputs/model above. On receipt of the correction,
compare it against that archive and verify that only the stated metadata
changed before recording independent acceptance. Do not retrain, resplit or
inspect S3 outcomes for this housekeeping update. This lab correction does
not complete the separate CIC acceptance issue.
