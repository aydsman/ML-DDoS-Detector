"""Benchmark provenance guards and held-out isolation; no fragile speed assertions."""
import json

import pytest

from ddos_detector.training import train
from ddos_detector.training_data import prepare_data
from tools.benchmark_models import benchmark
from tools.compare_baselines import compare
from tools.create_training_demo import create_demo


def test_benchmark_only_scores_validation_and_preserves_artifacts(tmp_path):
    source = create_demo(tmp_path / "source")
    data = prepare_data(source / "records.json", source / "manifest.json", allow_synthetic=True)
    forest, comparison = tmp_path / "forest", tmp_path / "comparison"
    train(data, forest, n_estimators=4)
    compare(data, forest, comparison)
    artifacts = {p: p.read_bytes() for d in (forest, comparison) for p in d.iterdir()}
    for split in ("train", "test"):
        for row in data.rows[split]:
            row["vector"] = ("must-not-score-or-fit",)
    output = tmp_path / "timing"
    report = benchmark(data, forest, comparison, output, rounds=2, warmup=1)
    assert report["status"] == "synthetic-code-check"
    assert report["final_test_scored"] is False
    assert report["model_settings_changed"] is False
    assert report["model_order_per_round"] == [["random_forest", "mlp"], ["mlp", "random_forest"]]
    for value in report["models"].values():
        assert value["summary"]["calls"] == 2 * len(data.rows["validation"])
        assert value["summary"]["min_ms"] <= value["summary"]["median_ms"] <= value["summary"]["max_ms"]
    assert all(p.read_bytes() == content for p, content in artifacts.items())
    assert json.loads((output / "summary.json").read_text()) == report
    with pytest.raises(ValueError, match="new benchmark"):
        benchmark(data, forest, comparison, output)
    with pytest.raises(ValueError, match="positive"):
        benchmark(data, forest, comparison, tmp_path / "invalid", rounds=0)
    data.manifest_sha256 = "changed"
    with pytest.raises(ValueError, match="frozen"):
        benchmark(data, forest, comparison, tmp_path / "mismatch")
    data.manifest_sha256 = report["manifest_sha256"]
    with (comparison / "mlp.joblib").open("ab") as handle:
        handle.write(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        benchmark(data, forest, comparison, tmp_path / "tampered")
