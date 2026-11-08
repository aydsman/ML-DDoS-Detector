"""Ali's synthetic label-rule checks from docs/dataset-plan.md.

These exercise the existing loader with hand-assigned expected labels. They do
not review CIC files, packet/flow joins, benign evidence, or split independence.
"""
import copy
import json

import pytest

from ddos_detector.training_data import prepare_data
from tools.create_training_demo import create_demo


@pytest.fixture
def inputs(tmp_path):
    root = create_demo(tmp_path / "synthetic-label-contract")
    records = root / "records.json"
    return records, root / "manifest.json", json.loads(records.read_text())


def case_row(template, *, selected=10, attacks=8, label="attack", start=100, **changes):
    """Add a synthetic window without removing the scaffold's required classes."""
    row = copy.deepcopy(template)
    row.update(
        window_id=f"synthetic-label-case-{start}",
        window_start=start,
        window_end=start + 1,
        packet_count=selected,
        attack_labelled_packets=attacks,
        unknown_packets=0,
        capture_state="valid",
        capped=False,
        boundary=False,
        inside_attack_interval=False,
        label=label,
        label_reason="Manually specified synthetic dataset-plan acceptance case",
    )
    row.update(changes)
    # Hand-calculated features for selected one-source, 60-byte SYN packets in
    # one second. Their independently supplied labels are the test inputs;
    # neither packet flags nor a model prediction determine the expected label.
    row["features"] = None if label == "excluded" else {
        "packet_rate": selected,
        "byte_rate": selected * 60,
        "syn_count": selected,
        "syn_ack_ratio": selected,
        "syn_no_ack_share": 1,
        "pkt_size_mean": 60,
        "pkt_size_std": 0,
        "unique_src_ips": 1,
        "src_ip_entropy": 0,
        "tcp_share": 1,
        "udp_share": 0,
        "icmp_share": 0,
    }
    return row


def load_cases(inputs, cases):
    records, manifest, scaffold = inputs
    records.write_text(json.dumps([*scaffold, *cases]), encoding="utf-8")
    return prepare_data(records, manifest, allow_synthetic=True)


# Expected labels/reasons are literal acceptance decisions, not calculated by a
# copy of the production label selector. Multiple conditions check which reason
# remains visible when a window must be excluded for more than one cause.
@pytest.mark.parametrize("changes,label,reason", [
    pytest.param({}, "attack", None, id="8-of-10-is-exactly-80-percent"),
    pytest.param({"selected": 100, "attacks": 80}, "attack", None,
                 id="80-of-100-is-exactly-80-percent"),
    pytest.param({"attacks": 9}, "attack", None, id="above-80-percent"),
    pytest.param({"attacks": 7}, "excluded", "mixed", id="7-of-10-is-below-80-percent"),
    pytest.param({"selected": 100, "attacks": 79}, "excluded", "mixed",
                 id="79-of-100-is-below-80-percent"),
    pytest.param({"attacks": 0}, "benign", None, id="benign-outside-attack-interval"),
    pytest.param({"attacks": 0, "inside_attack_interval": True},
                 "excluded", "interval_without_attack", id="no-confirmed-attack-inside-interval"),
    pytest.param({"unknown_packets": 1}, "excluded", "unknown",
                 id="unknown-overrides-80-percent-attack"),
    pytest.param({"boundary": True}, "excluded", "boundary",
                 id="boundary-overrides-80-percent-attack"),
    pytest.param({"capture_state": "failed"}, "excluded", "unavailable",
                 id="failed-coverage-overrides-80-percent-attack"),
    pytest.param({"capture_state": "missing"}, "excluded", "unavailable",
                 id="missing-coverage-overrides-80-percent-attack"),
    pytest.param({"capture_state": "uncertain"}, "excluded", "unavailable",
                 id="uncertain-coverage-overrides-80-percent-attack"),
    pytest.param({"capped": True}, "excluded", "capped",
                 id="capped-overrides-80-percent-attack"),
    pytest.param({"capture_state": "failed", "capped": True,
                  "unknown_packets": 1, "boundary": True},
                 "excluded", "unavailable", id="coverage-priority-over-other-exclusions"),
    pytest.param({"capped": True, "unknown_packets": 1, "boundary": True},
                 "excluded", "capped", id="capped-priority-over-unknown-and-boundary"),
    pytest.param({"unknown_packets": 1, "boundary": True},
                 "excluded", "unknown", id="unknown-priority-over-boundary"),
    pytest.param({"selected": 0, "attacks": 0, "boundary": True},
                 "excluded", "boundary", id="boundary-priority-over-empty"),
    pytest.param({"attacks": 7, "boundary": True},
                 "excluded", "boundary", id="boundary-priority-over-mixed"),
])
def test_dataset_plan_label_decisions(inputs, changes, label, reason):
    row = case_row(inputs[2][0], label=label, **changes)
    data = load_cases(inputs, [row])
    kept = [r for r in data.rows["train"] if r["window_id"] == row["window_id"]]
    assert [r["label"] for r in kept] == ([] if label == "excluded" else [label])
    assert data.excluded == ({} if reason is None else {reason: 1})
    assert len(data.rows["train"]) == (12 if label == "excluded" else 13)
    assert len(data.rows["validation"]) == len(data.rows["test"]) == 12
    assert data.summary()["data_kind"] == "synthetic"

    # A matching supplied label alone is insufficient: the same evidence must
    # reject every alternative label, specifically at the label-evidence check.
    for wrong_label in {"benign", "attack", "excluded"} - {label}:
        wrong = {**row, "label": wrong_label}
        with pytest.raises(ValueError, match="label conflicts with exclusion/packet-count evidence"):
            load_cases(inputs, [wrong])


def test_exclusion_summary_accounts_for_every_omitted_synthetic_window(inputs):
    changes = [
        {"unknown_packets": 1},
        {"unknown_packets": 1, "boundary": True},
        {"capture_state": "failed", "capped": True},
        {"capture_state": "missing"},
        {"capped": True},
        {"boundary": True},
        {"selected": 0, "attacks": 0},
        {"attacks": 7},
        {"attacks": 0, "inside_attack_interval": True},
    ]
    cases = [case_row(inputs[2][0], label="excluded", start=100 + i, **change)
             for i, change in enumerate(changes)]
    data = load_cases(inputs, cases)
    summary = data.summary()
    assert summary["excluded"] == {
        "unknown": 2,
        "unavailable": 2,
        "capped": 1,
        "boundary": 1,
        "empty": 1,
        "mixed": 1,
        "interval_without_attack": 1,
    }
    retained = [row for split_rows in data.rows.values() for row in split_rows]
    assert len(retained) == 36
    assert len(retained) + sum(summary["excluded"].values()) == len(inputs[2]) + len(cases)
    assert {row["window_id"] for row in retained}.isdisjoint(row["window_id"] for row in cases)
    assert all(split["windows"] == 12 for split in summary["splits"].values())
    assert summary["data_kind"] == "synthetic"
