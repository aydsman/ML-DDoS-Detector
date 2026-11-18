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
