import csv
import json
import struct

import pytest

from tools import lab_session_export as lse

T0 = 1_800_000_000
SERVER, ATTACKER, CLIENT, STRAY = "10.10.10.10", "10.10.10.30", "10.10.10.20", "10.10.10.99"


def ip_frame(src, proto, l4, dst=SERVER):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    return b"\x00" * 12 + b"\x08\x00" + header + l4


def tcp(flags, dport=80):
    return struct.pack("!HHIIBBHHH", 40000, dport, 0, 0, 5 << 4, flags, 0, 0, 0)


def udp(dport=9999):
    return struct.pack("!HHHH", 40000, dport, 8, 0)


def write_pcap(path, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in sorted(packets, key=lambda item: item[0]):
            us = round(ts * 1_000_000)
            handle.write(struct.pack("<IIII", us // 1_000_000, us % 1_000_000, len(data), len(data)))
            handle.write(data)


def write_csv(path, fields, rows):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def scenario_run(root, run_id, protocol, times, state="complete"):
    folder = root / run_id
    folder.mkdir(parents=True)
    write_csv(folder / "activity.csv", ["run_id", "packet_index", "started_at", "epoch_seconds", "elapsed_ms",
                                        "ip_bytes", "outcome", "error_type"],
              [{"run_id": run_id, "packet_index": i + 1, "started_at": "", "epoch_seconds": t, "elapsed_ms": 0.1,
                "ip_bytes": 40, "outcome": "sent", "error_type": ""} for i, t in enumerate(times)])
    (folder / "run.json").write_text(json.dumps({
        "schema_version": "scenario-draft-1", "run_id": run_id, "state": state, "activity_file": "activity.csv",
        "settings": {"protocol": protocol, "rate": 0, "duration": 0, "port": 80 if protocol == "syn" else 9999},
        "summary": {"sent": len(times)}}), encoding="utf-8")


def client_run(root, times):
    root.mkdir(parents=True)
    write_csv(root / "requests.csv", ["run_id", "request_index", "started_at", "epoch_seconds", "elapsed_ms",
                                      "outcome", "status_code", "error_type"],
              [{"run_id": "c", "request_index": i + 1, "started_at": "", "epoch_seconds": t, "elapsed_ms": 2,
                "outcome": "ok", "status_code": 200, "error_type": ""} for i, t in enumerate(times)])
    (root / "run.json").write_text(json.dumps({"schema_version": "draft-2", "run_id": "c", "state": "complete",
                                               "settings": {"rate": 10}, "requests_file": "requests.csv"}),
                                   encoding="utf-8")


def steps(start, stop, step):
    n = round((stop - start) / step)
    return [round(start + i * step, 6) for i in range(n)]


@pytest.fixture
def session(tmp_path):
    """Client 10 pps for 55 s; SYN run 50 pps at 15-25 s; UDP run 20 pps at 30-45 s; one stray packet at 5.5 s."""
    client_times = steps(T0, T0 + 55.1, 0.1)
    syn_times = steps(T0 + 15, T0 + 25, 0.02)
    udp_times = steps(T0 + 30, T0 + 45, 0.05)
    packets = [(t, ip_frame(CLIENT, 6, tcp(0x10))) for t in client_times]
    packets += [(t, ip_frame(ATTACKER, 6, tcp(0x02))) for t in syn_times]
    packets += [(t + 0.001, ip_frame(ATTACKER, 6, tcp(0x04))) for t in syn_times]  # RST replies
    packets += [(t, ip_frame(ATTACKER, 17, udp())) for t in udp_times]
    packets += [(T0 + 5.5, ip_frame(STRAY, 17, udp()))]
    write_pcap(tmp_path / "server.pcap", packets)
    runs = tmp_path / "scenarios"
    scenario_run(runs, "a-syn", "syn", syn_times)
    scenario_run(runs, "b-udp", "udp", udp_times)
    scenario_run(runs, "z-stale", "syn", [], state="running")
    client_run(tmp_path / "client", client_times)
    return tmp_path


def run_export(session, **kwargs):
    manifest = lse.export("S1", session / "server.pcap", session / "scenarios", session / "client",
                          session / "out", tcpdump_dropped=0, **kwargs)
    rows = {row["window_start"] - T0: row for row in map(json.loads, (session / "out" / "windows.jsonl").open())}
    return manifest, rows


def test_labels_follow_the_lab_pilot_rules(session):
    manifest, rows = run_export(session)
    assert rows[0]["exclusion_reason"] == rows[55]["exclusion_reason"] == "capture edge"
    assert rows[5]["exclusion_reason"] == "non-client packets outside attack runs"
    assert all(rows[s]["label"] == "benign" for s in (*range(1, 5), *range(6, 12), *range(48, 55)))
    for second in (*range(12, 18), *range(22, 33), *range(42, 48)):
        assert rows[second]["exclusion_reason"] == "run start/stop boundary", second
    for second in range(18, 22):  # 50 SYN + 50 RST + 10 client = 90.9% attack
        assert (rows[second]["label"], rows[second]["attack_protocol"]) == ("attack", "syn")
        assert rows[second]["attack_packets"] == 100
    for second in range(33, 42):  # 20 UDP + 10 client = 66.7% attack
        assert rows[second]["exclusion_reason"] == "inside attack run, attack share below 80% (mixed)"
    assert manifest["window_counts"]["attack"] == 4 and manifest["window_counts"]["syn"] == 4
    assert manifest["windows_total"] == 56 and manifest["window_packet_count_mismatches"] == 0
    assert manifest["packet_labels"] == {"benign": 551, "attack": 1300, "unknown": 1}


def test_source_counts_sum_to_packet_count_and_count_syn_only(session):
    _, rows = run_export(session)
    for row in rows.values():
        assert sum(item["packets"] for item in row["source_counts"]) == row["packet_count"]
    attacker_tcp = next(i for i in rows[19]["source_counts"] if (i["src"], i["proto"]) == (ATTACKER, "tcp"))
    assert attacker_tcp == {"src": ATTACKER, "proto": "tcp", "packets": 100, "syn_only": 50}
    assert rows[19]["features"]["syn_count"] == 50


def test_sent_matches_captured_and_stale_run_is_ignored(session):
    manifest, _ = run_export(session)
    assert [(r["protocol"], r["sent_equals_captured"]) for r in manifest["attack_runs"]] == [("syn", True), ("udp", True)]
    assert [r["run_id"] for r in manifest["ignored_attack_runs"]] == ["z-stale"]
    assert manifest["capture"]["valid_for_scoring"] is True
    assert manifest["original_reported_counts"]["attack"] == 253
    assert len(manifest["capture"]["sha256"]) == 64 and len(manifest["windows_sha256"]) == 64


def test_attacker_offset_moves_run_boundaries(session):
    _, rows = run_export(session, offset_attacker=-3.0)  # runs logged 3 s late relative to the server
    assert rows[19]["exclusion_reason"] == "run start/stop boundary"  # 25 - 3 = 22 boundary now covers 19..24
    assert rows[16]["label"] == "attack"  # run now 12-22 s: attack windows 15..18
    assert rows[9]["exclusion_reason"] == "run start/stop boundary"  # 15 - 3 = 12 covers 9..14


def test_refuses_to_overwrite_an_export(session):
    run_export(session)
    with pytest.raises(FileExistsError):
        run_export(session)


def test_scores_only_when_capture_has_no_drops(session, monkeypatch):
    from ddos_detector import training
    monkeypatch.setattr(training, "load_model", lambda _: ("pipe", {"model_sha256": "m", "decision_threshold": 0.5}))
    monkeypatch.setattr(training, "score_loaded_record",
                        lambda pipe, meta, record: {"attack_score": record["features"]["packet_rate"] / 1000})
    _, rows = run_export(session, model="model-dir")
    assert rows[19]["score"] == {"attack_score": 0.11}
    manifest = lse.export("S1", session / "server.pcap", session / "scenarios", session / "client",
                          session / "out2", tcpdump_dropped=3, model="model-dir")
    assert manifest["capture"]["valid_for_scoring"] is False
    assert all(json.loads(line)["score"] is None for line in (session / "out2" / "windows.jsonl").open())
