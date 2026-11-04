"""Validate labelled packet-window records without creating or guessing labels."""
import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .config import FEATURE_NAMES
from .contracts import FEATURE_SCHEMA_VERSION, feature_vector

SCOPE = "protected_server_inbound_ipv4_tcp_udp_icmp"
SIZE_DEFINITION = "ipv4_total_length_bytes"
SPLITS = ("train", "validation", "test")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    return value


def count(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


@dataclass
class PreparedData:
    manifest: dict
    rows: dict
    excluded: dict
    input_sha256: str
    manifest_sha256: str

    def summary(self):
        return {
            "data_kind": self.manifest["data_kind"],
            "input_sha256": self.input_sha256,
            "manifest_sha256": self.manifest_sha256,
            "splits": {split: {"windows": len(rows), "labels": dict(Counter(r["label"] for r in rows)),
                                "run_ids": sorted({r["run_id"] for r in rows})}
                       for split, rows in self.rows.items()},
            "excluded": self.excluded,
        }


def prepare_data(records_path, manifest_path, *, allow_synthetic=False):
    """Read a JSON array of enriched windows plus independently reviewed split manifest.

    Reviews are recorded attestations, not automated proof of ground truth.
    No random split, imputation, packet labelling or capture extraction occurs here.
    """
    manifest = read_json(manifest_path)
    if manifest.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("Unsupported feature schema version")
    if manifest.get("feature_names") != FEATURE_NAMES:
        raise ValueError("Feature order must match the contract")
    if manifest.get("scope") != SCOPE or manifest.get("size_definition") != SIZE_DEFINITION:
        raise ValueError("Capture scope/packet-size definition is incompatible")
    if manifest.get("window_alignment") != "unix_epoch":
        raise ValueError("Windows must be epoch aligned")
    duration = number(manifest.get("window_seconds"), "window_seconds")
    if duration != 1.0:
        raise ValueError("This baseline supports the agreed one-second windows only")
    kind = manifest.get("data_kind")
    if kind == "synthetic":
        if not allow_synthetic:
            raise ValueError("Synthetic data needs explicit --allow-synthetic")
    elif kind == "reviewed_packet_windows":
        for field in ("labels", "splits", "feature_parity"):
            text(manifest.get("review_refs", {}).get(field), f"review_refs.{field}")
    else:
        raise ValueError("data_kind must be synthetic or reviewed_packet_windows")
    runs, captures = manifest.get("runs"), manifest.get("captures")
    if not isinstance(runs, dict) or not runs or not isinstance(captures, dict) or not captures:
        raise ValueError("Explicit runs and captures are required")
    capture_split = {}
    for run_id, run in runs.items():
        text(run_id, "run_id")
        if run.get("split") not in SPLITS or not run.get("capture_ids"):
            raise ValueError("Each run needs a split and capture_ids")
        for capture_id in run["capture_ids"]:
            if capture_id not in captures:
                raise ValueError("Run references an unknown capture")
            if capture_id in capture_split and capture_split[capture_id] != run["split"]:
                raise ValueError("A capture cannot cross splits")
            capture_split[capture_id] = run["split"]
    hashes = {}
    for capture_id, capture in captures.items():
        text(capture_id, "capture_id")
        sha = text(capture.get("sha256"), "capture.sha256").lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ValueError("Capture SHA-256 must be 64 hexadecimal characters")
        text(capture.get("label_metadata_reference"), "label_metadata_reference")
        if capture_id not in capture_split:
            raise ValueError("Capture has no assigned run")
        if sha in hashes and hashes[sha] != capture_split[capture_id]:
            raise ValueError("Identical capture content cannot cross splits")
        hashes[sha] = capture_split[capture_id]
    raw = read_json(records_path)
    if not isinstance(raw, list) or not raw:
        raise ValueError("Records must be a nonempty JSON array")
    rows = {split: [] for split in SPLITS}
    excluded = Counter()
    ids, windows = set(), set()
    for row in raw:
        if not isinstance(row, dict):
            raise ValueError("Each window must be an object")
        window_id = text(row.get("window_id"), "window_id")
        if window_id in ids:
            raise ValueError("Duplicate window_id")
        ids.add(window_id)
        run_id, capture_id = row.get("run_id"), row.get("capture_id")
        if run_id not in runs or capture_id not in runs[run_id]["capture_ids"]:
            raise ValueError("Window capture/run provenance does not match manifest")
        start = number(row.get("window_start"), "window_start")
        end = number(row.get("window_end"), "window_end")
        if start != math.floor(start) or not math.isclose(end-start, duration, abs_tol=1e-9):
            raise ValueError("Window boundaries must match the one-second epoch grid")
        key = (captures[capture_id]["sha256"].lower(), start, end)
        if key in windows:
            raise ValueError("Duplicate capture window")
        windows.add(key)
        selected = count(row.get("packet_count"), "packet_count")
        unknown = count(row.get("unknown_packets"), "unknown_packets")
        attacks = count(row.get("attack_labelled_packets"), "attack_labelled_packets")
        if attacks + unknown > selected:
            raise ValueError("Packet label counts exceed selected packets")
        for field in ("boundary", "inside_attack_interval", "capped"):
            if type(row.get(field)) is not bool:
                raise ValueError(f"{field} must be an explicit boolean")
        if row.get("capture_state") not in ("valid", "failed", "missing", "uncertain"):
            raise ValueError("Explicit capture_state is required")
        text(row.get("label_reason"), "label_reason")
        if row["capture_state"] != "valid": reason = "unavailable"
        elif row["capped"]: reason = "capped"
        elif unknown: reason = "unknown"
        elif row["boundary"]: reason = "boundary"
        elif not selected: reason = "empty"
        elif attacks / selected >= .8: reason = None
        elif attacks: reason = "mixed"
        elif row["inside_attack_interval"]: reason = "interval_without_attack"
        else: reason = None
        expected = "excluded" if reason else ("attack" if attacks else "benign")
        if row.get("label") != expected:
            raise ValueError(f"{window_id}: label conflicts with exclusion/packet-count evidence")
        if reason:
            excluded[reason] += 1
            continue
        values = feature_vector(row.get("features"), feature_schema_version=manifest["feature_schema_version"])
        f = row["features"]
        if not math.isclose(f["packet_rate"] * duration, selected, rel_tol=1e-9):
            raise ValueError("packet_rate disagrees with packet_count")
        if not math.isclose(sum(f[n] for n in ("tcp_share", "udp_share", "icmp_share")), 1.0, abs_tol=1e-9):
            raise ValueError("Protocol shares must sum to one")
        if not 1 <= f["unique_src_ips"] <= selected or f["syn_count"] > selected:
            raise ValueError("Source/SYN counts exceed packet bounds")
        rows[runs[run_id]["split"]].append({**row, "vector": values})
    for split in SPLITS:
        rows[split].sort(key=lambda r: r["window_id"])
        if {r["label"] for r in rows[split]} != {"benign", "attack"}:
            raise ValueError(f"{split} needs eligible benign and attack examples")
    return PreparedData(manifest, rows, dict(excluded), file_sha256(records_path), file_sha256(manifest_path))
