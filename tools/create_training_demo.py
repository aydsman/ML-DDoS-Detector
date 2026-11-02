"""Create deliberately synthetic fixtures to exercise W2 code, not measure accuracy."""
import argparse
import hashlib
import json
from pathlib import Path

from ddos_detector.config import FEATURE_NAMES
from ddos_detector.features import Packet, extract_features
from ddos_detector.training_data import SCOPE, SIZE_DEFINITION


def create_demo(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {"data_kind": "synthetic", "feature_schema_version": "1", "feature_names": FEATURE_NAMES,
                "window_seconds": 1.0, "window_alignment": "unix_epoch", "scope": SCOPE,
                "size_definition": SIZE_DEFINITION, "review_refs": {}, "runs": {}, "captures": {}}
    rows = []
    for split in ("train", "validation", "test"):
        for kind in ("benign", "syn", "udp"):
            run_id = f"synthetic-{split}-{kind}"
            manifest["runs"][run_id] = {"split": split, "capture_ids": [run_id]}
            manifest["captures"][run_id] = {"sha256": hashlib.sha256(run_id.encode()).hexdigest(),
                "label_metadata_reference": "synthetic fixture definition; no real capture or independent ground truth"}
            for index in range(4):
                count = 10+index if kind == "benign" else 60+index
                proto, flags = ("udp", 0) if kind == "udp" else ("tcp", 0x10 if kind == "benign" else 0x02)
                packets = [Packet(index+.1, f"10.10.10.{20 if kind == 'benign' else 30}", proto,
                                  120 if kind == "benign" else 60, flags) for _ in range(count)]
                rows.append({"window_id": f"{run_id}-{index}", "run_id": run_id, "capture_id": run_id,
                    "window_start": index, "window_end": index+1, "packet_count": count,
                    "attack_labelled_packets": 0 if kind == "benign" else count,
                    "unknown_packets": 0, "boundary": False, "inside_attack_interval": kind != "benign",
                    "capture_state": "valid", "capped": False,
                    "label": "benign" if kind == "benign" else "attack",
                    "label_reason": "synthetic fixture only", "features": extract_features(packets, 1.0)})
    for filename, value in (("manifest.json", manifest), ("records.json", rows)):
        (directory/filename).write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
    sample = {"feature_schema_version": "1", "window_seconds": 1.0, "capture_state": "valid",
              "capped": False, "features": rows[0]["features"]}
    (directory/"score-record.json").write_text(json.dumps(sample, indent=2)+"\n",encoding="utf-8")
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    create_demo(args.output)
    print("Synthetic fixtures created. Any resulting metrics are software checks, not project accuracy.")
