import json
from pathlib import Path

import pytest

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.contracts import feature_vector
from ddos_detector.features import Packet, extract_features


def example_record():
    return extract_features([Packet(100.1, "10.10.10.30", "tcp", 60, 2)], 1.0)


def test_shuffled_input_preserves_model_feature_order():
    record = example_record()
    shuffled = dict(reversed(list(record.items())))
    assert feature_vector(shuffled, feature_schema_version="1") == tuple(
        float(record[name]) for name in FEATURE_NAMES
    )


def test_published_feature_contract_matches_runtime_order():
    path = Path(__file__).resolve().parents[1] / "docs" / "feature-contract.json"
    published = json.loads(path.read_text())
    assert published["feature_names"] == FEATURE_NAMES
    assert [f["name"] for f in published["features"]] == FEATURE_NAMES


@pytest.mark.parametrize("name,value", [
    ("byte_rate", None), ("byte_rate", float("nan")),
    ("byte_rate", float("inf")), ("packet_rate", -1),
    ("syn_count", 1.5), ("unique_src_ips", True),
    ("tcp_share", 1.01), ("udp_share", "0.5"),
    ("byte_rate", 10 ** 400),
])
def test_invalid_measurements_are_rejected(name, value):
    record = example_record()
    record[name] = value
    with pytest.raises(ValueError):
        feature_vector(record, feature_schema_version="1")


@pytest.mark.parametrize("mutation", ["missing", "extra", "version"])
def test_schema_mismatch_is_rejected(mutation):
    record = example_record()
    if mutation == "missing":
        del record["syn_count"]
    elif mutation == "extra":
        record["source_ip"] = "10.10.10.30"
    with pytest.raises(ValueError):
        feature_vector(record, feature_schema_version="2" if mutation == "version" else "1")
