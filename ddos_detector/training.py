"""Reproducible baseline training; verified data and final-test evaluation are separate."""
import argparse
import json
import math
import platform
from pathlib import Path
import sys
import subprocess

import scipy

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

from .config import FEATURE_NAMES
from .contracts import FEATURE_SCHEMA_VERSION, feature_vector
from .training_data import SCOPE, SIZE_DEFINITION, file_sha256, prepare_data, read_json


ARTIFACT_VERSION = "1"


def versions():
    return {"python": platform.python_version(), "numpy": np.__version__,
            "scikit_learn": sklearn.__version__, "scipy": scipy.__version__, "joblib": joblib.__version__}


def source_revision():
    root = Path(__file__).resolve().parent.parent
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                                capture_output=True, text=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, check=True,
                                    capture_output=True, text=True).stdout.strip())
        return {"git_commit": commit, "git_dirty": dirty}
    except (OSError, subprocess.CalledProcessError):
        return {"git_commit": None, "git_dirty": None}


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def metrics(labels, scores, threshold):
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Threshold must be finite and between zero and one")
    if len(labels) != len(scores) or not labels:
        raise ValueError("Metrics need nonempty matching labels and scores")
    if any(type(y) is not int or y not in (0, 1) for y in labels):
        raise ValueError("Labels must be binary integers")
    if any(not math.isfinite(float(s)) or not 0 <= s <= 1 for s in scores):
        raise ValueError("Scores must be finite and between zero and one")
    counts = {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
    for actual, score in zip(labels, scores):
        counts[("tn", "fp", "fn", "tp")[2 * actual + int(score >= threshold)]] += 1
    tn, fp, fn, tp = (counts[k] for k in ("tn", "fp", "fn", "tp"))
    def ratio(n, d):
        return n / d if d else None
    return {**counts, "confusion_matrix": [[tn, fp], [fn, tp]], "class_order": ["benign", "attack"],
            "samples": len(labels), "threshold": threshold, "accuracy": ratio(tp+tn, len(labels)),
            "precision": ratio(tp, tp+fp), "recall": ratio(tp, tp+fn),
            "f1": ratio(2*tp, 2*tp+fp+fn), "false_positive_rate": ratio(fp, fp+tn),
            "undefined_metric_reason": "A null ratio has zero denominator."}


def xy(rows):
    return np.asarray([r["vector"] for r in rows], dtype=np.float64), [int(r["label"] == "attack") for r in rows]


def attack_scores(pipeline, matrix):
    position = list(pipeline.classes_).index(1)
    return pipeline.predict_proba(matrix)[:, position].tolist()


def train(data, output_dir, *, seed=3670, n_estimators=100, threshold=.5):
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("Seed must be a uint32 integer")
    if type(n_estimators) is not int or not 1 <= n_estimators <= 1000:
        raise ValueError("Trees must be an integer between 1 and 1000")
    if isinstance(threshold, bool) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Threshold must be finite and between zero and one")
    output = Path(output_dir)
    if output.exists():
        raise ValueError("Use a new output directory; previous artifacts must not be overwritten")
    x_train, y_train = xy(data.rows["train"])
    x_val, y_val = xy(data.rows["validation"])
    pipeline = Pipeline([("forest", RandomForestClassifier(
        n_estimators=n_estimators, random_state=seed, n_jobs=1, class_weight="balanced"))])
    pipeline.fit(x_train, y_train)
    scores = attack_scores(pipeline, x_val)
    summary = data.summary()
    evaluation = {"status": "synthetic-code-check" if data.manifest["data_kind"] == "synthetic" else "validation-evaluation",
                  "split": "validation", "metrics": metrics(y_val, scores, threshold),
                  "predictions": [{"window_id": r["window_id"], "label": r["label"], "attack_score": s}
                                  for r, s in zip(data.rows["validation"], scores)],
                  "final_test_scored": False, "data": summary}
    metadata = {"artifact_version": ARTIFACT_VERSION, "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_names": list(FEATURE_NAMES), "dtype": "float64", "window_seconds": 1.0,
                "window_alignment": "unix_epoch", "scope": SCOPE, "size_definition": SIZE_DEFINITION,
                "preprocessing": "none-no-imputation-or-scaling", "model_type": "RandomForestClassifier",
                "score_interpretation": "aggregate forest vote probability; not calibrated or source confidence",
                "decision_threshold": threshold, "threshold_selection": "explicit baseline/validation-only setting",
                "seed": seed, "n_estimators": n_estimators, "class_weight": "balanced", "n_jobs": 1,
                "classes": [0, 1], "versions": versions(), "data": summary,
                "review_refs": data.manifest.get("review_refs", {}), "source_revision": source_revision(),
                "model_file": "model.joblib"}
    output.mkdir(parents=True, exist_ok=False)
    joblib.dump(pipeline, output / "model.joblib")
    metadata["model_sha256"] = file_sha256(output / "model.joblib")
    metadata["model_version"] = metadata["model_sha256"]
    write_json(output / "validation.json", evaluation)
    # Published last: its presence identifies a fully saved model package.
    write_json(output / "metadata.json", metadata)
    loaded, _ = load_model(output)
    if not np.array_equal(pipeline.predict_proba(x_val), loaded.predict_proba(x_val)):
        raise RuntimeError("Saved/reloaded probabilities differ")
    return metadata, evaluation


def load_model(directory):
    """Load only a locally generated/trusted joblib package (pickle can execute code)."""
    directory = Path(directory)
    meta = read_json(directory / "metadata.json")
    expected = {"artifact_version": ARTIFACT_VERSION, "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "feature_names": FEATURE_NAMES, "dtype": "float64", "window_seconds": 1.0,
                "window_alignment": "unix_epoch", "scope": SCOPE, "size_definition": SIZE_DEFINITION,
                "preprocessing": "none-no-imputation-or-scaling", "model_file": "model.joblib",
                "model_type": "RandomForestClassifier", "classes": [0, 1]}
    for key, value in expected.items():
        if meta.get(key) != value:
            raise ValueError(f"Incompatible model metadata: {key}")
    recorded = meta.get("versions")
    runtime = versions()
    # Preserve full versions as provenance; Python patch releases may differ
    # across the training PC and lab VM. ML libraries still match exactly.
    python_parts = recorded.get("python", "").split(".") if isinstance(recorded, dict) and isinstance(recorded.get("python"), str) else []
    if (not isinstance(recorded, dict) or recorded.keys() != runtime.keys()
            or len(python_parts) != 3 or not all(part.isdecimal() for part in python_parts)
            or python_parts[:2] != runtime["python"].split(".")[:2]
            or any(recorded[key] != value for key, value in runtime.items() if key != "python")):
        raise ValueError("Model package requires matching Python major.minor and exact ML dependency versions")
    threshold = meta.get("decision_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (float, int)) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Invalid saved threshold")
    if meta.get("model_sha256") != file_sha256(directory / "model.joblib"):
        raise ValueError("Model checksum mismatch")
    pipeline = joblib.load(directory / "model.joblib")
    if (not isinstance(pipeline, Pipeline) or list(pipeline.named_steps) != ["forest"]
            or not isinstance(pipeline.named_steps["forest"], RandomForestClassifier)
            or pipeline.n_features_in_ != len(FEATURE_NAMES) or list(pipeline.classes_) != [0, 1]):
        raise ValueError("Saved estimator is incompatible with the metadata")
    return pipeline, meta


def score_record(directory, record):
    pipeline, meta = load_model(directory)
    if record.get("capture_state") != "valid" or record.get("capped") is not False:
        raise ValueError("Inference requires valid coverage and uncapped source counts")
    if (record.get("feature_schema_version") != meta["feature_schema_version"]
            or type(record.get("window_seconds")) not in (int, float) or record.get("window_seconds") != 1.0):
        raise ValueError("Inference feature schema/window is incompatible")
    vector = feature_vector(record.get("features"), feature_schema_version=record["feature_schema_version"])
    if vector[0] <= 0:
        raise ValueError("Empty windows are excluded from inference")
    score = attack_scores(pipeline, np.asarray([vector], dtype=np.float64))[0]
    return {"scope": "aggregate", "source_ip": None, "attack_score": score,
            "predicted_attack": score >= meta["decision_threshold"],
            "decision_threshold": meta["decision_threshold"], "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "model_sha256": meta["model_sha256"], "data_kind": meta["data"]["data_kind"]}


def final_test(data, directory, output_path):
    pipeline, meta = load_model(directory)
    if data.input_sha256 != meta["data"]["input_sha256"] or data.manifest_sha256 != meta["data"]["manifest_sha256"]:
        raise ValueError("Final test must use the frozen input/manifest recorded at training")
    # A new output is mandatory. Operators must not repeat final tests to tune models.
    if Path(output_path).exists():
        raise ValueError("Final-test output exists; do not overwrite or tune against it")
    matrix, labels = xy(data.rows["test"])
    result = {"status": "synthetic-code-check" if data.manifest["data_kind"] == "synthetic" else "final-test-evaluation",
              "split": "test", "model_sha256": meta["model_sha256"],
              "metrics": metrics(labels, attack_scores(pipeline, matrix), meta["decision_threshold"]),
              "input_sha256": data.input_sha256, "manifest_sha256": data.manifest_sha256}
    write_json(output_path, result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "train", "final-test"):
        p = sub.add_parser(name)
        p.add_argument("--records", required=True)
        p.add_argument("--manifest", required=True)
        p.add_argument("--allow-synthetic", action="store_true")
        if name == "train":
            p.add_argument("--output", required=True)
            p.add_argument("--seed", type=int, default=3670)
            p.add_argument("--trees", type=int, default=100)
            p.add_argument("--threshold", type=float, default=.5)
        if name == "final-test":
            p.add_argument("--model", required=True)
            p.add_argument("--output", required=True)
    score = sub.add_parser("score")
    score.add_argument("--model", required=True)
    score.add_argument("--record", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "score":
            result = score_record(args.model, read_json(args.record))
        else:
            data = prepare_data(args.records, args.manifest, allow_synthetic=args.allow_synthetic)
            if args.command == "prepare": result = data.summary()
            elif args.command == "train":
                meta, evaluation = train(data, args.output, seed=args.seed, n_estimators=args.trees, threshold=args.threshold)
                result = {"output": str(Path(args.output).resolve()), "status": evaluation["status"],
                          "validation": evaluation["metrics"], "final_test_scored": False,
                          "model_sha256": meta["model_sha256"]}
            else: result = final_test(data, args.model, args.output)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
