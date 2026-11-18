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
