"""Offline aggregate model comparisons on the reviewed train/validation splits."""
import argparse
import warnings
from pathlib import Path

import joblib
import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.training import (
    attack_scores, load_model, metrics, source_revision, versions, write_json, xy,
)
from ddos_detector.training_data import file_sha256, prepare_data


def compare(data, forest_directory, output_directory):
    output = Path(output_directory)
    if output.exists():
        raise ValueError("Use a new comparison directory")
    forest, forest_meta = load_model(forest_directory)
    if (forest_meta["data"]["input_sha256"] != data.input_sha256
            or forest_meta["data"]["manifest_sha256"] != data.manifest_sha256):
        raise ValueError("Comparison inputs must match the frozen forest inputs")

    train_matrix, train_labels = xy(data.rows["train"])
    validation_matrix, validation_labels = xy(data.rows["validation"])
    mlp = Pipeline([
        ("scale", StandardScaler()),
        ("mlp", MLPClassifier(hidden_layer_sizes=(16,), solver="lbfgs",
                              alpha=0.0001, max_iter=1000, random_state=3670)),
    ])
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always", ConvergenceWarning)
        mlp.fit(train_matrix, train_labels)
    convergence_warnings = [str(item.message) for item in captured
                            if issubclass(item.category, ConvergenceWarning)]
    scores = attack_scores(mlp, validation_matrix)
    candidates = [metrics(validation_labels, scores, threshold)
                  for threshold in (0.3, 0.5, 0.7)]
    selected = max(candidates, key=lambda result: (
        result["f1"] if result["f1"] is not None else -1,
        -result["fp"], -abs(result["threshold"] - 0.5), -result["threshold"],
    ))

    rate_index = FEATURE_NAMES.index("packet_rate")
    benign_rates = train_matrix[np.asarray(train_labels) == 0, rate_index]
    rate_threshold = float(np.max(benign_rates))
    rule_scores = (validation_matrix[:, rate_index] > rate_threshold).astype(float).tolist()
    forest_scores = attack_scores(forest, validation_matrix)
    report = {
        "status": "synthetic-code-check" if data.manifest["data_kind"] == "synthetic" else "validation-comparison",
        "split": "validation", "final_test_scored": False, "data": data.summary(),
        "random_forest": metrics(validation_labels, forest_scores, forest_meta["decision_threshold"]),
        "mlp": selected, "mlp_threshold_candidates": candidates,
        "threshold_selection": "Highest validation F1, then fewer false positives, then closest to 0.5, then lower threshold.",
        "aggregate_rate_rule": {
            "formula": "packet_rate > maximum benign training packet_rate",
            "rate_threshold_packets_per_second": rate_threshold,
            "metrics": metrics(validation_labels, rule_scores, 0.5),
        },
        "convergence_warnings": convergence_warnings,
        "predictions": [
            {"window_id": row["window_id"], "label": row["label"],
             "forest_score": forest_score, "mlp_score": mlp_score, "rate_rule": bool(rule_score)}
            for row, forest_score, mlp_score, rule_score in zip(
                data.rows["validation"], forest_scores, scores, rule_scores)
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    joblib.dump(mlp, output / "mlp.joblib")
    reloaded = joblib.load(output / "mlp.joblib")
    if not np.array_equal(mlp.predict_proba(validation_matrix), reloaded.predict_proba(validation_matrix)):
        raise RuntimeError("Saved MLP predictions differ after reload")
    metadata = {
        "artifact_kind": "offline-baseline-comparison", "feature_names": list(FEATURE_NAMES),
        "versions": versions(), "source_revision": source_revision(),
        "forest_model_sha256": forest_meta["model_sha256"],
        "mlp_model_sha256": file_sha256(output / "mlp.joblib"),
        "data": data.summary(), "review_refs": data.manifest.get("review_refs", {}),
        "scaler": "StandardScaler fitted on training rows only",
        "mlp_parameters": mlp.named_steps["mlp"].get_params(),
        "mlp_decision_threshold": selected["threshold"],
        "deployment_status": "Offline comparison; model adoption requires a separate decision.",
    }
    write_json(output / "validation.json", report)
    write_json(output / "metadata.json", metadata)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--forest", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-synthetic", action="store_true")
    args = parser.parse_args(argv)
    data = prepare_data(args.records, args.manifest, allow_synthetic=args.allow_synthetic)
    report = compare(data, args.forest, args.output)
    for name in ("random_forest", "mlp"):
        print(name, report[name]["confusion_matrix"], "F1", report[name]["f1"])
    print("aggregate_rate_rule", report["aggregate_rate_rule"]["metrics"]["confusion_matrix"])
    print("Final test scored:", report["final_test_scored"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
