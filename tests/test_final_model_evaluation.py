"""Release gates, frozen identities, and synthetic-only held-out comparison."""
import json

import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.training import train
from ddos_detector.training_data import file_sha256, prepare_data, read_json
from tools.compare_baselines import compare
from tools.create_training_demo import create_demo
import tools.evaluate_frozen_models as evaluator


@pytest.fixture
def packages(tmp_path):
    source = create_demo(tmp_path / "source")
    records, manifest = source / "records.json", source / "manifest.json"
    data = prepare_data(records, manifest, allow_synthetic=True)
    forest, comparison = tmp_path / "forest", tmp_path / "comparison"
    train(data, forest, n_estimators=4)
    comparison_report = compare(data, forest, comparison)
    paths = {"records": records, "manifest": manifest,
             "forest_model": forest / "model.joblib",
             "forest_metadata": forest / "metadata.json",
             "forest_validation": forest / "validation.json",
             "mlp_model": comparison / "mlp.joblib",
             "comparison_metadata": comparison / "metadata.json",
             "comparison_validation": comparison / "validation.json"}
    freeze = {"schema": "final-model-evaluation-v1", "status": "approved",
              "approval_ref": "synthetic-test-fixture-only", "feature_schema_version": "1",
              "evaluation_models": ["random_forest", "mlp", "aggregate_rate_rule"],
              "feature_names": list(FEATURE_NAMES),
              "artifacts": {name: file_sha256(path) for name, path in paths.items()},
              "thresholds": {"random_forest": 0.5,
                             "mlp": read_json(comparison / "metadata.json")["mlp_decision_threshold"],
                             "aggregate_rate_packets_per_second": comparison_report["aggregate_rate_rule"]["rate_threshold_packets_per_second"]}}
    freeze_path = tmp_path / "freeze.json"
    freeze_path.write_text(json.dumps(freeze))
    return records, manifest, forest, comparison, freeze_path, paths, data


def test_unreleased_invocations_do_not_read_data(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unapproved final evaluation accessed data/models")
    monkeypatch.setattr(evaluator, "prepare_data", forbidden)
    monkeypatch.setattr(evaluator, "load_model", forbidden)
    proposed = tmp_path / "freeze.json"
    proposed.write_text(json.dumps({"schema": "final-model-evaluation-v1", "status": "proposed"}))
    args = ("missing-records", "missing-manifest", "missing-forest", "missing-mlp",
            proposed, tmp_path / "output.json")
    with pytest.raises(ValueError, match="explicit"):
        evaluator.run(*args)
    with pytest.raises(ValueError, match="approved freeze"):
        evaluator.run(*args, confirmed=True)


def test_synthetic_final_comparison_never_refits_or_scores_other_splits(packages, tmp_path, monkeypatch):
    records, manifest, forest, comparison, freeze_path, paths, data = packages
    originals = {path: path.read_bytes() for path in paths.values()}
    for split in ("train", "validation"):
        for row in data.rows[split]:
            row["vector"] = ("must-not-score-this-split",)
    monkeypatch.setattr(evaluator, "prepare_data", lambda *a, **kw: data)
    def forbidden(*args, **kwargs):
        pytest.fail("Final evaluation tried to fit a model")
    for cls in (RandomForestClassifier, MLPClassifier, StandardScaler):
        monkeypatch.setattr(cls, "fit", forbidden)
    output = tmp_path / "final.json"
    report = evaluator.run(records, manifest, forest, comparison, freeze_path, output,
                           confirmed=True, allow_synthetic=True)
    assert report["status"] == "synthetic-code-check"
    assert report["split"] == "test" and report["models_refitted"] is False
    assert report["results"]["random_forest"]["confusion_matrix"] == [[4, 0], [0, 8]]
    assert report["results"]["mlp"]["confusion_matrix"] == [[4, 0], [0, 8]]
    assert set(report["results"]) == {"random_forest", "mlp", "aggregate_rate_rule"}
    assert all(r["samples"] == len(data.rows["test"]) for r in report["results"].values())
    assert len(report["predictions"]) == len(data.rows["test"])
    assert {p: p.read_bytes() for p in originals} == originals
    with pytest.raises(ValueError, match="output exists"):
        evaluator.run(records, manifest, forest, comparison, freeze_path, output,
                      confirmed=True, allow_synthetic=True)


@pytest.mark.parametrize("artifact", ["records", "manifest", "mlp_model", "forest_metadata", "comparison_validation"])
def test_changed_frozen_artifact_refused_before_data_or_model_access(packages, tmp_path, monkeypatch, artifact):
    records, manifest, forest, comparison, freeze_path, paths, _ = packages
    with paths[artifact].open("ab") as handle:
        handle.write(b" ")
    def forbidden(*args, **kwargs):
        pytest.fail("Changed artifact was used")
    monkeypatch.setattr(evaluator, "prepare_data", forbidden)
    monkeypatch.setattr(evaluator, "load_model", forbidden)
    with pytest.raises(ValueError, match="Frozen artifact changed"):
        evaluator.run(records, manifest, forest, comparison, freeze_path, tmp_path / "final.json",
                      confirmed=True, allow_synthetic=True)
