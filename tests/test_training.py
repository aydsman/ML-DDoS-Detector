"""W2 regressions: leakage, label exclusions, fit isolation and artifact compatibility."""
import copy
import json
from pathlib import Path

import numpy as np
import pytest

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.training import final_test, load_model, main, metrics, score_record, train
from ddos_detector.training_data import prepare_data
from tools.create_training_demo import create_demo


@pytest.fixture
def inputs(tmp_path):
    root = create_demo(tmp_path / "input")
    return root, root / "records.json", root / "manifest.json"


def rewrite(path, transform):
    value = json.loads(path.read_text(encoding="utf-8"))
    transform(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def prepare(inputs):
    _, records, manifest = inputs
    return prepare_data(records, manifest, allow_synthetic=True)


def test_synthetic_requires_opt_in_and_preserves_provenance(inputs):
    _, records, manifest = inputs
    with pytest.raises(ValueError, match="Synthetic"):
        prepare_data(records, manifest)
    data = prepare(inputs)
    assert data.summary()["data_kind"] == "synthetic"
    assert {s: len(r) for s,r in data.rows.items()} == {"train": 12, "validation": 12, "test": 12}
    assert data.rows["train"][0]["vector"] == tuple(data.rows["train"][0]["features"][n] for n in FEATURE_NAMES)


@pytest.mark.parametrize("mutation,match", [
    (lambda m: m.update(feature_names=list(reversed(FEATURE_NAMES))), "order"),
    (lambda m: m.update(feature_schema_version="2"), "schema"),
    (lambda m: m.update(window_alignment="first_packet"), "aligned"),
    (lambda m: m.update(window_seconds=2), "one-second"),
    (lambda m: m.update(data_kind="reviewed_packet_windows"), "review_refs"),
    (lambda m: m["runs"]["synthetic-test-benign"].update(capture_ids=["synthetic-train-benign"]), "cross splits"),
    (lambda m: m["captures"]["synthetic-test-benign"].update(sha256=m["captures"]["synthetic-train-benign"]["sha256"]), "content cannot cross"),
])
def test_manifest_rejects_incompatible_or_leaking_inputs(inputs, mutation, match):
    rewrite(inputs[2], mutation)
    with pytest.raises(ValueError, match=match): prepare(inputs)


@pytest.mark.parametrize("mutation,match", [
    (lambda rows: rows.append(copy.deepcopy(rows[0])), "Duplicate window_id"),
    (lambda rows: rows[0].update(window_start=.1, window_end=1.1), "epoch grid"),
    (lambda rows: rows[0].update(unknown_packets=1), "label conflicts"),
    (lambda rows: rows[0].update(capped=True), "label conflicts"),
    (lambda rows: rows[0]["features"].update(packet_rate=100), "packet_count"),
    (lambda rows: rows[0]["features"].update(tcp_share=.2), "sum to one"),
    (lambda rows: rows[0]["features"].update(syn_count=True), "numeric"),
    (lambda rows: rows[0].update(run_id="missing"), "provenance"),
    (lambda rows: rows[0]["features"].pop("byte_rate"), "exactly"),
])
def test_records_reject_bad_labels_features_and_provenance(inputs, mutation, match):
    rewrite(inputs[1], mutation)
    with pytest.raises(ValueError, match=match): prepare(inputs)


@pytest.mark.parametrize("field,value,reason", [
    ("unknown_packets", 1, "unknown"), ("boundary", True, "boundary"),
    ("capped", True, "capped"), ("capture_state", "failed", "unavailable"),
    ("inside_attack_interval", True, "interval_without_attack"),
])
def test_excluded_windows_are_counted_not_imputed(inputs, field, value, reason):
    def change(rows): rows[0].update({field: value, "label": "excluded", "label_reason": reason, "features": None})
    rewrite(inputs[1], change)
    data = prepare(inputs)
    assert data.excluded == {reason: 1}
    assert len(data.rows["train"]) == 11


def test_mixed_empty_boundary_and_duplicate_capture_window(inputs):
    def change(rows):
        rows[0].update(packet_count=0, label="excluded", label_reason="empty", features=None)
        rows[4].update(attack_labelled_packets=30, label="excluded", label_reason="mixed", features=None)
    rewrite(inputs[1], change)
    assert prepare(inputs).excluded == {"empty": 1, "mixed": 1}
    def duplicate(rows):
        row = copy.deepcopy(rows[1]); row["window_id"] = "other-id"; rows.append(row)
    rewrite(inputs[1], duplicate)
    with pytest.raises(ValueError, match="Duplicate capture window"): prepare(inputs)


def test_binary_metrics_are_independently_known():
    result = metrics([0,0,1,1], [.1,.7,.3,.9], .5)
    assert result["confusion_matrix"] == [[1,1],[1,1]]
    assert result["precision"] == result["recall"] == result["f1"] == result["false_positive_rate"] == .5
    result = metrics([0,0], [0,0], .5)
    assert result["precision"] is None and result["recall"] is None


def test_train_fits_only_training_records_and_never_scores_test(inputs, tmp_path, monkeypatch):
    from sklearn.ensemble import RandomForestClassifier
    data = prepare(inputs)
    original_fit = RandomForestClassifier.fit
    seen = []
    def inspect_fit(self, matrix, labels, **kwargs):
        seen.append((matrix.copy(), list(labels)))
        return original_fit(self, matrix, labels, **kwargs)
    monkeypatch.setattr(RandomForestClassifier, "fit", inspect_fit)
    # If training accesses the final-test vectors it will fail.
    for row in data.rows["test"]: row["vector"] = ("must-not-score-test",)
    meta, report = train(data, tmp_path/"model", n_estimators=8)
    assert len(seen) == 1
    assert np.array_equal(seen[0][0], [r["vector"] for r in data.rows["train"]])
    assert report["final_test_scored"] is False
    assert report["status"] == "synthetic-code-check"
    assert meta["preprocessing"] == "none-no-imputation-or-scaling"


def test_repeatability_save_reload_and_separate_final_test(inputs, tmp_path):
    data = prepare(inputs)
    first, second = tmp_path/"model1", tmp_path/"model2"
    meta1, report1 = train(data, first, n_estimators=8)
    meta2, report2 = train(data, second, n_estimators=8)
    assert report1["predictions"] == report2["predictions"]
    sample = json.loads((inputs[0]/"score-record.json").read_text())
    assert score_record(first, sample) == score_record(first, sample)
    output = tmp_path/"final-test.json"
    result = final_test(data, first, output)
    assert result["split"] == "test" and result["status"] == "synthetic-code-check"
    with pytest.raises(ValueError, match="exists"): final_test(data, first, output)
    with pytest.raises(ValueError, match="overwritten"): train(data, first)
    data.input_sha256 = "different"
    with pytest.raises(ValueError, match="frozen"): final_test(data, first, tmp_path/"another.json")


@pytest.mark.parametrize("mutation,match", [
    (lambda m:m.update(feature_names=list(reversed(FEATURE_NAMES))), "feature_names"),
    (lambda m:m.update(window_seconds=2), "window_seconds"),
    (lambda m:m.update(feature_schema_version="2"), "schema"),
    (lambda m:m.update(decision_threshold=float("nan")), "threshold"),
    (lambda m:m["versions"].update(scikit_learn="wrong"), "versions"),
    (lambda m:m.update(model_sha256="0"*64), "checksum"),
])
def test_model_loader_rejects_incompatible_or_changed_artifacts(inputs, tmp_path, mutation, match):
    output = tmp_path/"model"
    train(prepare(inputs), output, n_estimators=4)
    rewrite(output/"metadata.json",mutation)
    with pytest.raises(ValueError, match=match): load_model(output)


@pytest.mark.parametrize("change", [
    {"capture_state":"failed"}, {"capped":True}, {"feature_schema_version":"2"}, {"window_seconds":2},
])
def test_inference_requires_compatible_coverage(inputs,tmp_path,change):
    output=tmp_path/"model"; train(prepare(inputs),output,n_estimators=4)
    record=json.loads((inputs[0]/"score-record.json").read_text());record.update(change)
    with pytest.raises(ValueError): score_record(output,record)


def test_duplicate_json_keys_rejected(inputs):
    inputs[2].write_text('{"data_kind":"synthetic","data_kind":"reviewed_packet_windows"}')
    with pytest.raises(ValueError,match="Duplicate JSON key"):prepare(inputs)


def test_cli_prepare_train_score_and_final_test(inputs,tmp_path,capsys):
    base=["--records",str(inputs[1]),"--manifest",str(inputs[2]),"--allow-synthetic"]
    assert main(["prepare",*base])==0
    assert main(["train",*base,"--output",str(tmp_path/"model"),"--trees","4"])==0
    assert main(["score","--model",str(tmp_path/"model"),"--record",str(inputs[0]/"score-record.json")])==0
    assert main(["final-test",*base,"--model",str(tmp_path/"model"),"--output",str(tmp_path/"test.json")])==0
    assert 'synthetic-code-check' in capsys.readouterr().out


def test_model_loader_allows_python_patch_change_and_preserves_provenance(inputs, tmp_path):
    from ddos_detector.training import versions
    output = tmp_path / "model"
    train(prepare(inputs), output, n_estimators=4)
    sample = json.loads((inputs[0] / "score-record.json").read_text())
    before = score_record(output, sample)
    recorded_python = ".".join(versions()["python"].split(".")[:2]) + ".999"
    rewrite(output / "metadata.json", lambda m: m["versions"].update(python=recorded_python))
    _, metadata = load_model(output)
    assert metadata["versions"]["python"] == recorded_python
    assert score_record(output, sample) == before


@pytest.mark.parametrize("key,value", [
    ("python", "3.13.0"), ("python", "2.12.0"), ("python", "3.12"),
    ("python", "3.12.bad"), ("python", None), ("python", 3.12),
    ("numpy", "different"), ("scikit_learn", "different"),
    ("scipy", "different"), ("joblib", "different"),
])
def test_model_loader_rejects_other_version_mismatches(inputs, tmp_path, key, value):
    output = tmp_path / "model"
    train(prepare(inputs), output, n_estimators=4)
    rewrite(output / "metadata.json", lambda m: m["versions"].update({key: value}))
    with pytest.raises(ValueError, match="versions"):
        load_model(output)
