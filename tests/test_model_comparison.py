"""Check train-only scaling, frozen inputs and held-out test isolation."""
import joblib
import numpy as np
import pytest

from ddos_detector.training import train, xy
from ddos_detector.training_data import prepare_data, read_json
from tools.compare_baselines import compare
from tools.create_training_demo import create_demo


def test_comparison_preserves_test_and_fits_scaler_on_training_only(tmp_path):
    source = create_demo(tmp_path / "source")
    data = prepare_data(source / "records.json", source / "manifest.json", allow_synthetic=True)
    forest = tmp_path / "forest"
    train(data, forest, n_estimators=4)
    training, _ = xy(data.rows["train"])
    for row in data.rows["test"]:
        row["vector"] = ("must-not-score-test",)
    output = tmp_path / "comparison"
    report = compare(data, forest, output)
    assert report["final_test_scored"] is False
    assert report["status"] == "synthetic-code-check"
    assert len(report["predictions"]) == len(data.rows["validation"])
    pipeline = joblib.load(output / "mlp.joblib")
    assert np.array_equal(pipeline.named_steps["scale"].mean_, training.mean(axis=0))
    assert pipeline.named_steps["scale"].n_samples_seen_ == len(training)
    assert report["aggregate_rate_rule"]["rate_threshold_packets_per_second"] == 13
    assert report["random_forest"]["confusion_matrix"] == [[4, 0], [0, 8]]
    assert read_json(output / "metadata.json")["artifact_kind"] == "offline-baseline-comparison"
    with pytest.raises(ValueError, match="new comparison"):
        compare(data, forest, output)
    data.manifest_sha256 = "changed"
    with pytest.raises(ValueError, match="frozen"):
        compare(data, forest, tmp_path / "mismatched")
