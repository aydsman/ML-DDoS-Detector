"""Explicitly released final classification comparison; never train or tune models."""
import argparse
from pathlib import Path

import joblib
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.training import (
    attack_scores, load_model, metrics, source_revision, validate_runtime_versions,
    versions, write_json, xy,
)
from ddos_detector.training_data import file_sha256, prepare_data, read_json


def require_release(freeze, output, confirmed):
    if not confirmed:
        raise ValueError("Final test requires explicit --confirm-final-test")
    if (freeze.get("schema") != "final-model-evaluation-v1"
            or freeze.get("status") != "approved"
            or not isinstance(freeze.get("approval_ref"), str)
            or not freeze["approval_ref"].strip()):
        raise ValueError("Final test requires an approved freeze and actual review reference")
    if Path(output).exists():
        raise ValueError("Final-test output exists; never overwrite or retune against it")
    if (freeze.get("evaluation_models") != ["random_forest", "mlp", "aggregate_rate_rule"]
            or freeze.get("feature_names") != list(FEATURE_NAMES)
            or freeze.get("feature_schema_version") != "1"):
        raise ValueError("Unsupported frozen evaluation contract")


def check_artifacts(freeze, records, manifest, forest, comparison):
    paths = {
        "records": Path(records), "manifest": Path(manifest),
        "forest_model": Path(forest) / "model.joblib",
        "forest_metadata": Path(forest) / "metadata.json",
        "forest_validation": Path(forest) / "validation.json",
        "mlp_model": Path(comparison) / "mlp.joblib",
        "comparison_metadata": Path(comparison) / "metadata.json",
        "comparison_validation": Path(comparison) / "validation.json",
    }
    if set(freeze.get("artifacts", {})) != set(paths):
        raise ValueError("Expected every frozen input and model artifact")
    for key, path in paths.items():
        if file_sha256(path) != freeze["artifacts"][key]:
            raise ValueError(f"Frozen artifact changed: {key}")


def evaluate(data, forest, comparison, freeze, output, *, confirmed=False):
    require_release(freeze, output, confirmed)
    model, meta = load_model(forest)
    comparison = Path(comparison)
    mlp_meta = read_json(comparison / "metadata.json")
    validate_runtime_versions(mlp_meta.get("versions"))
    if (mlp_meta.get("artifact_kind") != "offline-baseline-comparison"
            or mlp_meta.get("feature_names") != list(FEATURE_NAMES)
            or mlp_meta.get("forest_model_sha256") != meta["model_sha256"]
            or mlp_meta.get("mlp_model_sha256") != file_sha256(comparison / "mlp.joblib")):
        raise ValueError("Incompatible frozen comparison")
    for metadata in (meta, mlp_meta):
        if (metadata["data"]["input_sha256"] != data.input_sha256
                or metadata["data"]["manifest_sha256"] != data.manifest_sha256
                or metadata["data"]["input_sha256"] != freeze["artifacts"]["records"]
                or metadata["data"]["manifest_sha256"] != freeze["artifacts"]["manifest"]):
            raise ValueError("Final test must use frozen training inputs and split manifest")
    thresholds = freeze["thresholds"]
    validation = read_json(comparison / "validation.json")
    rule_threshold = validation["aggregate_rate_rule"]["rate_threshold_packets_per_second"]
    if (thresholds["random_forest"] != meta["decision_threshold"]
            or thresholds["mlp"] != mlp_meta["mlp_decision_threshold"]
            or thresholds["aggregate_rate_packets_per_second"] != rule_threshold):
        raise ValueError("Frozen thresholds differ from saved validation choices")
    mlp = joblib.load(comparison / "mlp.joblib")  # Trusted, checksum-verified team package only.
    if (not isinstance(mlp, Pipeline) or list(mlp.named_steps) != ["scale", "mlp"]
            or not isinstance(mlp.named_steps["scale"], StandardScaler)
            or not isinstance(mlp.named_steps["mlp"], MLPClassifier)
            or mlp.n_features_in_ != len(FEATURE_NAMES) or list(mlp.classes_) != [0, 1]):
        raise ValueError("Incompatible saved MLP pipeline")
    # No fit, threshold search, or train/validation prediction occurs.
    matrix, labels = xy(data.rows["test"])
    scores = {"random_forest": attack_scores(model, matrix),
              "mlp": attack_scores(mlp, matrix),
              "aggregate_rate_rule": (matrix[:, FEATURE_NAMES.index("packet_rate")] > rule_threshold).astype(float).tolist()}
    report = {
        "schema": "final-model-evaluation-v1",
        "status": "synthetic-code-check" if data.manifest["data_kind"] == "synthetic" else "final-test-evaluation",
        "split": "test", "approval_ref": freeze["approval_ref"],
        "data": data.summary(), "artifacts": freeze["artifacts"],
        "source_revision": source_revision(), "versions": versions(),
        "thresholds": thresholds, "final_test_scored": True, "models_refitted": False,
        "results": {name: metrics(labels, values, thresholds[name] if name != "aggregate_rate_rule" else 0.5)
                    for name, values in scores.items()},
        "predictions": [
            {"window_id": row["window_id"], "label": row["label"],
             **{name: values[i] for name, values in scores.items()}}
            for i, row in enumerate(data.rows["test"])],
        "scope": "Eligible aggregate-window classification only; no source-policy, live service, capture-loss or protection claim.",
    }
    # Caller checks hashes before loading; retain a fresh exclusive output.
    write_json(output, report)
    return report


def run(records, manifest, forest, comparison, freeze_path, output, *,
        confirmed=False, allow_synthetic=False):
    freeze = read_json(freeze_path)
    # Release checks precede reading the dataset or loading either estimator.
    require_release(freeze, output, confirmed)
    check_artifacts(freeze, records, manifest, forest, comparison)
    data = prepare_data(records, manifest, allow_synthetic=allow_synthetic)
    report = evaluate(data, forest, comparison, freeze, output, confirmed=confirmed)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("records", "manifest", "forest", "comparison", "freeze", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--confirm-final-test", action="store_true")
    parser.add_argument("--allow-synthetic", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = run(args.records, args.manifest, args.forest, args.comparison,
                     args.freeze, args.output, confirmed=args.confirm_final_test,
                     allow_synthetic=args.allow_synthetic)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print("Status:", report["status"])
    for name, result in report["results"].items():
        print(name, result["confusion_matrix"], "F1", result["f1"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
