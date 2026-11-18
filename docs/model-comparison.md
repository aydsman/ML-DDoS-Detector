# Offline baseline comparison

Run the initial Week 4 comparison with the same reviewed records and manifest
used to train the Week 2 Random Forest:

```sh
python -m tools.compare_baselines --records RECORDS --manifest MANIFEST --forest FOREST --output NEW_OUTPUT
```

The command verifies that the input hashes match the forest package. It fits
a StandardScaler and a single-hidden-layer MLP (16 units, L-BFGS, alpha 0.0001,
seed 3670, up to 1,000 iterations) on training rows only. It compares thresholds
0.3, 0.5 and 0.7 on validation data. Selection uses highest F1, fewer false
positives, closest to 0.5 and finally the lower threshold as tie breakers.
Convergence warnings are retained in the report.

The simple aggregate rule flags a packet rate greater than the highest benign
training packet rate. It is an experimental comparison rule. Per-source
mitigation needs separate source evidence and policy validation.

The existing forest keeps its saved threshold. The command records validation
scores and metrics for all three methods, saves the MLP with its fitted scaler,
verifies save/reload predictions, and writes package and dependency identities.
It never evaluates the held-out test split. The comparison package is identified
separately from the forest deployment package. Keep generated data and artifacts
under ignored results directories.

Synthetic fixtures require explicit `--allow-synthetic`. Their metrics are
software verification. Final model selection, inference-time benchmarking and
final test evaluation belong to the later model-freeze milestone.

## November 18 controlled-lab comparison

Used the frozen S1 training and S2 validation inputs recorded in PR #42.
Training contained 553 eligible windows, and validation contained 550.

| Method | True negatives | False positives | False negatives | True positives | Validation F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Saved Random Forest, threshold 0.5 | 300 | 0 | 0 | 250 | 1.0000 |
| StandardScaler + MLP, threshold 0.5 | 300 | 0 | 0 | 250 | 1.0000 |
| Aggregate packet rate > 42 packets/s | 296 | 4 | 0 | 250 | 0.9921 |

The three candidate MLP score thresholds tied on validation F1, so the
predefined tie breakers selected 0.5. Fitting produced no convergence warning.
Saved and reloaded MLP probabilities were identical.

The rate rule's threshold of 42 packets/s is the highest benign training rate,
measured only on this narrow dataset. Its validation false-positive rate was
4/300 (1.33%). It is not an approved source-blocking threshold.

Comparison implementation revision was `f4a3492`, with a clean worktree.
MLP SHA-256 is
`4ccca7213657ada1e114d5df0a79b28c6e26de9ffc78a113e7f7491bb6120393`.
Input/manifest checksums match the frozen Random Forest inputs in PR #42.
The comparison and model artifacts remain in the local ignored results folder.

S3 remains held out. The equal S2 scores do not distinguish the learned models
on broader workloads. The previously documented narrow traffic mix,
incident-source reset labels and eligible-window exclusions limit these
findings. W4 policy behavior and live acceptance are still pending.
