"""Time trusted saved models on validation windows only; never fit or score test rows."""
import argparse
from datetime import datetime, timezone
import os
import platform
from pathlib import Path
from time import perf_counter_ns

import joblib
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_info, threadpool_limits

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.training import load_model, source_revision, versions, write_json, xy
from ddos_detector.training_data import file_sha256, prepare_data, read_json


def summarize(samples_ns):
    values = np.asarray(samples_ns, dtype=np.float64) / 1_000_000
    return {"calls": len(samples_ns), "median_ms": float(np.median(values)),
            "p95_ms": float(np.percentile(values, 95)), "mean_ms": float(np.mean(values)),
            "min_ms": float(np.min(values)), "max_ms": float(np.max(values))}


def benchmark(data, forest_directory, comparison_directory, output_directory, *,
              rounds=5, warmup=50):
    """Measure batch-size-one predict_proba, including MLP scaling and validation."""
    if type(rounds) is not int or rounds < 1 or type(warmup) is not int or warmup < 1:
        raise ValueError("rounds and warmup must be positive integers")
    output = Path(output_directory)
    if output.exists():
        raise ValueError("Use a new benchmark directory")
    forest, forest_meta = load_model(forest_directory)
    directory = Path(comparison_directory)
    mlp_meta = read_json(directory / "metadata.json")
    if (mlp_meta.get("artifact_kind") != "offline-baseline-comparison"
            or mlp_meta.get("feature_names") != list(FEATURE_NAMES)):
        raise ValueError("Incompatible comparison metadata")
    for meta in (forest_meta, mlp_meta):
        if (meta["data"]["input_sha256"] != data.input_sha256
                or meta["data"]["manifest_sha256"] != data.manifest_sha256):
            raise ValueError("Benchmark inputs must match the frozen model inputs")
    if (mlp_meta.get("versions") != forest_meta["versions"]
            or mlp_meta.get("forest_model_sha256") != forest_meta["model_sha256"]):
        raise ValueError("Comparison must match the forest package and versions")
    mlp_hash = file_sha256(directory / "mlp.joblib")
    if mlp_meta.get("mlp_model_sha256") != mlp_hash:
        raise ValueError("MLP checksum mismatch")
    # Only locally generated/trusted packages: joblib loading can execute code.
    mlp = joblib.load(directory / "mlp.joblib")
    if (not isinstance(mlp, Pipeline) or list(mlp.named_steps) != ["scale", "mlp"]
            or not isinstance(mlp.named_steps["scale"], StandardScaler)
            or not isinstance(mlp.named_steps["mlp"], MLPClassifier)
            or mlp.n_features_in_ != len(FEATURE_NAMES) or list(mlp.classes_) != [0, 1]):
        raise ValueError("Incompatible MLP pipeline")
    if forest.named_steps["forest"].n_jobs != 1:
        raise ValueError("Benchmark requires the saved single-worker forest")
    # Intentionally never construct a train/test matrix here.
    matrix, _ = xy(data.rows["validation"])
    if not len(matrix):
        raise ValueError("Validation windows are required")
    windows = [np.ascontiguousarray(row.reshape(1, -1)) for row in matrix]
    models = {"random_forest": forest, "mlp": mlp}
    samples = {name: [] for name in models}
    results = {name: [] for name in models}
    orders = []
    with threadpool_limits(limits=1):
        pools = [{key: value for key, value in pool.items() if key != "filepath"}
                 for pool in threadpool_info()]
        for model in models.values():
            for i in range(warmup):
                model.predict_proba(windows[i % len(windows)])
        for round_index in range(rounds):
            order = list(models) if round_index % 2 == 0 else list(reversed(models))
            orders.append(order)
            for name in order:
                model = models[name]
                times = []
                # Same rotated validation order for both estimators in each round.
                for i in range(len(windows)):
                    window = windows[(i + round_index) % len(windows)]
                    start = perf_counter_ns()
                    model.predict_proba(window)
                    times.append(perf_counter_ns() - start)
                samples[name].extend(times)
                results[name].append(summarize(times))
    report = {
        "status": "synthetic-code-check" if data.manifest["data_kind"] == "synthetic"
                  else "local-validation-inference-benchmark",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": source_revision(), "versions": versions(),
        "environment": {"os": platform.platform(), "machine": platform.machine(),
                        "processor": platform.processor(),
                        "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER"),
                        "logical_cpus": os.cpu_count(), "native_thread_limit": 1,
                        "threadpools_during_benchmark": pools,
                        "isolation": "Ordinary desktop session; background load and power state not controlled"},
        "scope": "Warm batch-size-one Pipeline.predict_proba on prebuilt float64 arrays; "
                 "includes MLP scaling and estimator input validation, excludes loading, "
                 "feature extraction, record validation, logging, API, firewall and one-second accumulation",
        "timer": "perf_counter_ns", "warmup_calls_per_model": warmup,
        "rounds": rounds, "model_order_per_round": orders, "validation_windows": len(windows),
        "final_test_scored": False, "model_settings_changed": False,
        "input_sha256": data.input_sha256, "manifest_sha256": data.manifest_sha256,
        "models": {
            name: {"model_sha256": forest_meta["model_sha256"] if name == "random_forest" else mlp_hash,
                   "summary": summarize(samples[name]), "rounds": results[name]}
            for name in models},
        "limits": "Timing repetitions reuse validation windows, not independent traffic trials. "
                  "No VM, live detection latency, throughput, accuracy or model-adoption claim.",
    }
    # Raw per-call timings stay in ignored results; the bounded summary can be reviewed.
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "timings.json", samples)
    write_json(output / "summary.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("records", "manifest", "forest", "comparison", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--allow-synthetic", action="store_true")
    args = parser.parse_args(argv)
    data = prepare_data(args.records, args.manifest, allow_synthetic=args.allow_synthetic)
    report = benchmark(data, args.forest, args.comparison, args.output,
                       rounds=args.rounds, warmup=args.warmup)
    for name, value in report["models"].items():
        print(name, value["summary"])
    print("Final test scored:", report["final_test_scored"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
