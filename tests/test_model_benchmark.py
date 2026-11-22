"""Benchmark provenance guards and held-out isolation; no fragile speed assertions."""
import json

import pytest

from ddos_detector.training import load_model, train, versions
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

def test_benchmark_accepts_forest_from_another_python_patch(tmp_path):
    """Synthetic metadata simulation, not a claim of training on another patch."""
    source = create_demo(tmp_path / "source")
    data = prepare_data(source / "records.json", source / "manifest.json", allow_synthetic=True)
    forest, comparison = tmp_path / "forest", tmp_path / "comparison"
    train(data, forest, n_estimators=4)
    metadata_path = forest / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    parts = versions()["python"].split(".")
    simulated_patch = "0" if parts[2] != "0" else "1"
    metadata["versions"]["python"] = ".".join(parts[:2] + [simulated_patch])
    metadata_path.write_text(json.dumps(metadata))
    load_model(forest)
    compare(data, forest, comparison)
    comparison_meta = json.loads((comparison / "metadata.json").read_text())
    assert comparison_meta["versions"]["python"] == versions()["python"]
    assert comparison_meta["versions"]["python"] != metadata["versions"]["python"]
    for row in data.rows["test"]:
        row["vector"] = ("held-out-must-not-be-scored",)
    report = benchmark(data, forest, comparison, tmp_path / "timing", rounds=1, warmup=1)
    assert report["final_test_scored"] is False
    assert report["models"]["random_forest"]["model_sha256"] == metadata["model_sha256"]


@pytest.mark.parametrize("bad_version", [
    None, {}, {"python": "garbage"},
    {"python": "99.0.0"}, {"numpy": "incompatible"},
    {"unexpected": "1"},
])
def test_benchmark_rejects_incompatible_comparison_runtime(tmp_path, bad_version):
    source = create_demo(tmp_path / "source")
    data = prepare_data(source / "records.json", source / "manifest.json", allow_synthetic=True)
    forest, comparison = tmp_path / "forest", tmp_path / "comparison"
    train(data, forest, n_estimators=4)
    compare(data, forest, comparison)
    path = comparison / "metadata.json"
    metadata = json.loads(path.read_text())
    metadata["versions"] = (None if bad_version is None else
                            {} if bad_version == {} else {**versions(), **bad_version})
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="matching Python major.minor"):
        benchmark(data, forest, comparison, tmp_path / "timing", rounds=1, warmup=1)
