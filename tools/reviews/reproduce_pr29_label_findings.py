"""Reproduce two PR #29 label/provenance bugs using synthetic offline fixtures.

Run with the project Python 3.12 environment:
    python tools/reviews/reproduce_pr29_label_findings.py \
        --snapshot /path/to/review-pr29-83e62f2 --output /path/to/new-output

The reviewed join source is hash-pinned before import. No network activity,
source edits, real dataset inspection or training occurs. All generated files
stay under the explicitly selected fresh output directory.
"""
import argparse
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys

REVIEWED_HEAD = "83e62f2ad99dd63f81a5a963183632786bae95e9"
JOIN_SHA256 = "257298ffe3c4585a84b872404c4ad7f0a657a9f38201d5d3c13d0581fcbca8ba"
VICTIM = "192.168.50.1"
SOURCE = "172.16.0.5"
RUN_ID = "synthetic-pr29-review-only"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_reviewed_join(snapshot):
    source = snapshot / "tools" / "cic_flow_join.py"
    actual = digest(source)
    if actual != JOIN_SHA256:
        raise ValueError(f"Refusing unpinned join source: expected {JOIN_SHA256}, found {actual}")
    # Avoid bytecode files in the reviewed snapshot. Import the file directly so
    # an installed/current-checkout tools package cannot replace the pinned one.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    spec = importlib.util.spec_from_file_location("_reviewed_pr29_cic_flow_join", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dependency_hashes = {}
    for name, dependency in tuple(sys.modules.items()):
        if name == "ddos_detector" or name.startswith("ddos_detector."):
            path = Path(dependency.__file__).resolve()
            if not path.is_relative_to(snapshot):
                raise ValueError(f"Dependency {name} was loaded outside the reviewed snapshot: {path}")
            dependency_hashes[str(path.relative_to(snapshot))] = digest(path)
    return module, dependency_hashes


def tcp_frame(source_port=1000):
    transport = struct.pack("!HHIIBBHHH", source_port, 80, 0, 0, 5 << 4, 2, 0, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                     bytes(map(int, SOURCE.split("."))), bytes(map(int, VICTIM.split("."))))
    # Minimal parser fixtures with zero checksums, never transmitted as traffic.
    return bytes(12) + b"\x08\x00" + ip + transport


def write_pcap(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp_us, source_port in records:
            frame = tcp_frame(source_port)
            handle.write(struct.pack("<IIII", timestamp_us // 1_000_000,
                                     timestamp_us % 1_000_000, len(frame), len(frame)))
            handle.write(frame)


def write_flows(path, timestamp, duration):
    with path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Timestamp", "Flow Duration", "Label", "Source IP", "Source Port",
                         "Destination IP", "Destination Port", "Protocol"])
        writer.writerow([timestamp, duration, "Syn", SOURCE, 1000, VICTIM, 80, 6])


def run_join(join, directory, pieces):
    console = io.StringIO()
    with contextlib.redirect_stdout(console):
        join.main(["--csv", str(directory / "flows.csv"), "--pieces", *map(str, pieces),
                   "--victim", VICTIM, "--attack-label", "Syn", "--offset-hours", "0",
                   "--run-id", RUN_ID, "--out-dir", str(directory / "join-output")])
    with (directory / "join-stdout.txt").open("x", encoding="utf-8") as handle:
        handle.write(console.getvalue())
    windows = json.loads((directory / "join-output" / "windows.json").read_text())
    manifest = json.loads((directory / "join-output" / "manifest.json").read_text())
    return windows, manifest


def reproduce_boundaries(join, directory):
    directory.mkdir()
    piece = directory / "piece.pcap"
    write_pcap(piece, [(100_000_000, 2000), (101_200_000, 1000), (101_800_000, 1000),
                       (102_100_000, 1000), (103_000_000, 2000), (104_000_000, 2000)])
    write_flows(directory / "flows.csv", "1970-01-01 00:01:41.200000", 1_000_000)
    windows, _ = run_join(join, directory, [piece])
    fields = ("window_start", "window_end", "boundary", "inside_attack_interval",
              "label", "attack_labelled_packets", "unknown_packets")
    actual = [{key: row[key] for key in fields} for row in windows
              if row["window_start"] in (101, 102)]
    expected_bad = [
        {"window_start": 101.0, "window_end": 102.0, "boundary": False,
         "inside_attack_interval": False, "label": "attack", "attack_labelled_packets": 2,
         "unknown_packets": 0},
        {"window_start": 102.0, "window_end": 103.0, "boundary": False,
         "inside_attack_interval": False, "label": "attack", "attack_labelled_packets": 1,
         "unknown_packets": 0},
    ]
    return {"id": "missing-label-boundaries", "code_location": "tools/cic_flow_join.py:259-272",
            "expected_contract": "Windows crossing the attack interval edges 101.2/102.2 must be boundary exclusions.",
            "expected_buggy_behavior": expected_bad, "actual": actual,
            "reproduced": actual == expected_bad,
            "artifacts_directory": directory.name}


def reproduce_basenames(join, directory):
    directory.mkdir()
    first, second = directory / "a" / "piece.pcap", directory / "b" / "piece.pcap"
    write_pcap(first, [(100_000_000, 1000), (101_000_000, 1000), (102_000_000, 1000)])
    write_pcap(second, [(103_000_000, 1000), (104_000_000, 1000), (105_000_000, 1000)])
    write_flows(directory / "flows.csv", "1970-01-01 00:01:40", 6_000_000)
    windows, manifest = run_join(join, directory, [first, second])
    first_hash, second_hash = digest(first), digest(second)
    captures = manifest["captures"]
    ids = manifest["runs"][RUN_ID]["capture_ids"]
    earlier = [row for row in windows if row["window_start"] == 101.0]
    reproduced = (first_hash != second_hash and ids == ["piece.pcap", "piece.pcap"]
                  and set(captures) == {"piece.pcap"}
                  and captures["piece.pcap"]["sha256"] == second_hash
                  and len(earlier) == 1 and earlier[0]["capture_id"] == "piece.pcap"
                  and earlier[0]["label"] == "attack")
    return {"id": "duplicate-basename-provenance", "code_location": "tools/cic_flow_join.py:296-300",
            "expected_contract": "Distinct input files must retain distinct capture IDs/hashes, or duplicate IDs must be rejected.",
            "expected_buggy_behavior": "Both IDs become piece.pcap; only the second hash survives, including for the first file's window 101.",
            "actual": {"input_sha256": {"a/piece.pcap": first_hash, "b/piece.pcap": second_hash},
                       "run_capture_ids": ids, "manifest_captures": captures,
                       "earlier_window": [{key: row[key] for key in ("window_start", "capture_id", "label")}
                                          for row in earlier]},
            "reproduced": reproduced, "artifacts_directory": directory.name}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True, help="extracted PR #29 reviewed source tree")
    parser.add_argument("--output", type=Path, required=True, help="fresh directory below an existing parent")
    args = parser.parse_args(argv)
    snapshot, output = args.snapshot.expanduser().resolve(), args.output.expanduser().resolve()
    try:
        if output.exists():
            raise ValueError(f"Refusing to overwrite existing output: {output}")
        if not output.parent.is_dir():
            raise ValueError("The output parent must already exist")
        join, dependencies = load_reviewed_join(snapshot)
        output.mkdir(exist_ok=False)
    except (OSError, ValueError, ImportError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = {
        "evidence_kind": "synthetic_software_reproduction",
        "reviewed_pr": "https://github.com/aydsman/ML-DDoS-Detector/pull/29",
        "reviewed_head": REVIEWED_HEAD, "reviewed_join_sha256": JOIN_SHA256,
        "source_pin_scope": "tools/cic_flow_join.py; imported snapshot dependency hashes are recorded below",
        "snapshot": str(snapshot), "snapshot_dependency_sha256": dependencies,
        "limitations": ["No raw CIC PCAP/CSV was inspected; synthetic inputs cannot verify real dataset labels.",
                        "This reproduces bugs in the pinned source, without fixing it or approving training."],
        "findings": [],
    }
    for name, reproduce in (("boundary", reproduce_boundaries), ("basename-collision", reproduce_basenames)):
        try:
            report["findings"].append(reproduce(join, output / name))
        except (Exception, SystemExit) as exc:
            report["findings"].append({"id": name, "reproduced": False,
                                       "error": f"{type(exc).__name__}: {exc}", "artifacts_directory": name})
    reproduced = all(finding["reproduced"] for finding in report["findings"])
    report["status"] = "both_pinned_findings_reproduced" if reproduced else "findings_not_reproduced"
    with (output / "report.json").open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, allow_nan=False)
        handle.write("\n")
    print(json.dumps({"report": str(output / "report.json"), "status": report["status"]}))
    return 0 if reproduced else 1


if __name__ == "__main__":
    raise SystemExit(main())
