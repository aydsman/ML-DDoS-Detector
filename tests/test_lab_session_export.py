import csv
import json
import struct
import sys

import httpx
import pytest

from ddos_detector import http_client, scenarios
from ddos_detector.config import Config
from tools import lab_clock_check, lab_session_export as lse
from tools.lab_timing_check import NullSender

T0 = 1_800_000_000
SID = "policy-calibration-2030-01-15-a"
SERVER, ATTACKER, CLIENT, STRAY = "10.10.10.10", "10.10.10.30", "10.10.10.20", "10.10.10.99"
SYN_PLAN = {"protocol": "syn", "port": 80, "rate": 50, "duration": 10}
PACKETS = {}  # fixture packets per session folder, for tests that add to them
UDP_PLAN = {"protocol": "udp", "port": 9999, "rate": 20, "duration": 15}


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


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def scenario_run(root, run_id, plan, times, state="complete"):
    folder = root / run_id
    folder.mkdir(parents=True)
    write_csv(folder / "activity.csv", ["run_id", "packet_index", "started_at", "epoch_seconds", "elapsed_ms",
                                        "ip_bytes", "outcome", "error_type"],
              [{"run_id": run_id, "packet_index": i + 1, "started_at": "", "epoch_seconds": t, "elapsed_ms": 0.1,
                "ip_bytes": 40, "outcome": "sent", "error_type": ""} for i, t in enumerate(times)])
    write_json(folder / "run.json", {
        "schema_version": "scenario-draft-1", "run_id": run_id, "state": state, "activity_file": "activity.csv",
        "settings": {**plan, "target": SERVER, "interface": "enp0s8"},
        "summary": {"attempted": len(times), "sent": len(times)} if state == "complete" else None})


def client_run(root, times, state="complete"):
    """Shaped like http_client.RunExport output (draft-2)."""
    root.mkdir(parents=True)
    write_csv(root / "requests.csv", ["run_id", "request_index", "started_at", "epoch_seconds", "elapsed_ms",
                                      "outcome", "status_code", "error_type"],
              [{"run_id": "c", "request_index": i + 1, "started_at": "", "epoch_seconds": t, "elapsed_ms": 2,
                "outcome": "ok", "status_code": 200, "error_type": ""} for i, t in enumerate(times)])
    write_json(root / "run.json", {
        "schema_version": "draft-2", "run_id": "c", "traffic_type": "legitimate_http", "state": state,
        "settings": {"target": "http://10.10.10.10/", "timeout_seconds": 5.0, "request_rate": 10,
                     "duration_seconds": 55, "concurrency": 1},
        "summary": {"attempted": len(times)} if state == "complete" else None, "requests_file": "requests.csv"})


def clock_file(path, attacker=0.0, client=0.0, bound=0.01):
    write_json(path, {"vms": {name: {"offset_seconds": offset, "bound_seconds": bound,
                                    "host_epoch": T0 + (65 if "after" in path.name else -10), "samples": 20}
                              for name, offset in (("server", 0.0), ("client", client), ("attacker", attacker))}})
    return path


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
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    write_json(attacker / "schedule.json", {"session_id": SID, "client": {"rate": 10, "duration": 55},
                                            "runs": [SYN_PLAN, UDP_PLAN]})
    scenario_run(attacker / "scenarios", "a-syn", SYN_PLAN, syn_times)
    scenario_run(attacker / "scenarios", "b-udp", UDP_PLAN, udp_times)
    client_run(tmp_path / "client", client_times)
    clock_file(tmp_path / "clock-before.json")
    clock_file(tmp_path / "clock-after.json")
    PACKETS[tmp_path] = packets
    return tmp_path


def run_export(session, out="out", **kwargs):
    kwargs.setdefault("tcpdump_dropped", 0)
    kwargs.setdefault("clock_before", session / "clock-before.json")
    kwargs.setdefault("clock_after", session / "clock-after.json")
    manifest = lse.export(SID, session / "server.pcap", session / "attacker", session / "client",
                          session / out, **kwargs)
    rows = {row["window_start"] - T0: row for row in map(json.loads, (session / out / "windows.jsonl").open())}
    return manifest, rows


def test_labels_follow_the_lab_pilot_rules(session):
    manifest, rows = run_export(session)
    assert manifest["valid_for_scoring"] is True and manifest["problems"] == []
    assert rows[0]["exclusion_reason"] == rows[55]["exclusion_reason"] == "capture edge"
    assert rows[5]["exclusion_reason"] == "unknown packet labels"  # the stray packet
    assert all(rows[s]["label"] == "benign" for s in (*range(1, 5), *range(6, 12), *range(48, 55)))
    for second in (*range(12, 18), *range(22, 33), *range(42, 48)):
        assert rows[second]["exclusion_reason"] == "run start/stop boundary", second
    for second in range(18, 22):  # 50 SYN + 50 RST + 10 client = 90.9% attack
        assert (rows[second]["label"], rows[second]["attack_protocol"]) == ("attack", "syn")
        assert rows[second]["attack_packets"] == 100 and rows[second]["eligible_for_policy"] is True
    for second in range(33, 42):  # 20 UDP + 10 client = 66.7% attack
        assert rows[second]["exclusion_reason"] == "inside attack run, attack share below 80% (mixed)"
        assert rows[second]["eligible_for_policy"] is False
    assert manifest["window_counts"]["attack"] == 4 and manifest["window_counts"]["syn"] == 4
    assert manifest["windows_total"] == 56 and manifest["window_packet_count_mismatches"] == 0
    assert manifest["windows_eligible_for_policy"] == 4 + 17
    assert manifest["packet_labels"] == {"benign": 551, "attack": 1300, "unknown": 1}


def test_identity_is_new_and_unique(session):
    first, rows = run_export(session)
    second, _ = run_export(session, out="out2")
    assert first["session_id"] == SID and first["role"] == "calibration"
    assert first["session_uuid"] != second["session_uuid"]
    assert rows[19]["window_id"] == f"{SID}-{T0 + 19}" and rows[19]["session_uuid"] == first["session_uuid"]
    assert "original_reported_counts" not in first
    with pytest.raises(ValueError):
        lse.export("S1", session / "server.pcap", session / "attacker", session / "client", session / "bad")


def test_unknown_labels_exclude_a_window_before_the_80_percent_rule():
    tally = {"total": 100, "attack": 80, "benign": 10, "unknown": 10}
    run = {"start": T0 + 0.0, "stop": T0 + 100.0, "protocol": "syn"}
    labels = lse.label_windows({T0 + 10: tally, T0 + 50: tally, T0 + 90: tally}, [run], 2.5)
    assert labels[T0 + 50] == ("excluded", None, "unknown packet labels")


def test_unknown_packets_inside_an_attack_window_are_excluded_and_counted(session):
    extra = [(T0 + 19.3 + i * 0.01, ip_frame(STRAY, 17, udp())) for i in range(12)]  # 100/122 = 82% attack
    write_pcap(session / "server.pcap", PACKETS[session] + extra)
    _, rows = run_export(session)
    assert rows[19]["label"] == "excluded" and rows[19]["exclusion_reason"] == "unknown packet labels"
    assert rows[19]["unknown_packets"] == 12 and rows[19]["eligible_for_policy"] is False
    assert rows[20]["label"] == "attack"


def test_capped_windows_are_ineligible_and_unscored(session, monkeypatch):
    from ddos_detector import training
    monkeypatch.setattr(training, "load_model", lambda _: ("pipe", {"model_sha256": "m", "decision_threshold": 0.5}))
    monkeypatch.setattr(training, "score_loaded_record", lambda pipe, meta, record: {"attack_score": 1.0})
    _, rows = run_export(session, model="model-dir", config=Config(max_sources_per_window=1))
    for second in range(18, 22):
        assert rows[second]["capped"] is True
        assert rows[second]["eligible_for_policy"] is False
        assert "source cap reached" in rows[second]["ineligible_reasons"]
        assert rows[second]["score"] is None
    assert rows[2]["capped"] is False and rows[2]["score"] == {"attack_score": 1.0}


def test_unknown_tcp_flags_are_reported_not_counted_as_zero_syn(session):
    truncated = [(T0 + 2.5, ip_frame(CLIENT, 6, b"\x00" * 8))]  # TCP header not captured: flags unknown
    write_pcap(session / "server.pcap", PACKETS[session] + truncated)
    _, rows = run_export(session)
    client_tcp = next(i for i in rows[2]["source_counts"] if (i["src"], i["proto"]) == (CLIENT, "tcp"))
    assert client_tcp == {"src": CLIENT, "proto": "tcp", "packets": 11, "flags_known": 10,
                          "flags_unknown": 1, "syn_only": 0}
    assert rows[2]["tcp_flags_unknown_packets"] == 1
    assert rows[2]["eligible_for_policy"] is False and "unknown TCP flags" in rows[2]["ineligible_reasons"]


def test_source_counts_sum_to_packet_count_and_count_syn_only(session):
    _, rows = run_export(session)
    for row in rows.values():
        assert sum(item["packets"] for item in row["source_counts"]) == row["packet_count"]
    attacker_tcp = next(i for i in rows[19]["source_counts"] if (i["src"], i["proto"]) == (ATTACKER, "tcp"))
    assert attacker_tcp == {"src": ATTACKER, "proto": "tcp", "packets": 100, "flags_known": 100,
                            "flags_unknown": 0, "syn_only": 50}
    assert rows[19]["features"]["syn_count"] == 50


def test_sent_matches_captured(session):
    manifest, _ = run_export(session)
    assert [(r["protocol"], r["sent_equals_captured"]) for r in manifest["attack_runs"]] == [("syn", True), ("udp", True)]
    assert len(manifest["capture"]["sha256"]) == 64 and len(manifest["windows_sha256"]) == 64


def test_missing_attacker_folder_and_running_client_fail_closed(session, tmp_path_factory):
    empty = tmp_path_factory.mktemp("nothing")
    client = json.loads((session / "client" / "run.json").read_text())
    write_json(session / "client" / "run.json", {**client, "state": "running", "summary": None})
    manifest = lse.export(SID, session / "server.pcap", empty / "no-such-dir", session / "client", session / "out",
                          tcpdump_dropped=0, clock_before=session / "clock-before.json",
                          clock_after=session / "clock-after.json")
    assert manifest["valid_for_scoring"] is False
    assert manifest["attack_runs"] == []
    problems = " | ".join(manifest["problems"])
    assert "attack schedule missing" in problems and "attacker scenario folder missing" in problems
    assert "state 'running', not complete" in problems
    rows = [json.loads(line) for line in (session / "out" / "windows.jsonl").open()]
    assert rows and not any(row["eligible_for_policy"] for row in rows)


def test_missing_client_run_fails_closed(session, tmp_path_factory):
    manifest = lse.export(SID, session / "server.pcap", session / "attacker",
                          tmp_path_factory.mktemp("c") / "absent", session / "out", tcpdump_dropped=0,
                          clock_before=session / "clock-before.json", clock_after=session / "clock-after.json")
    assert manifest["valid_for_scoring"] is False and manifest["client_run"] is None
    assert any(p.startswith("client run missing") for p in manifest["problems"])


def test_failed_run_is_retained_and_inventory_is_enforced(session):
    scenario_run(session / "attacker" / "scenarios", "c-failed", SYN_PLAN, [], state="failed")
    manifest, _ = run_export(session)
    assert [r["run_id"] for r in manifest["retained_incomplete_attack_runs"]] == ["c-failed"]
    assert manifest["valid_for_scoring"] is False
    assert "attack run c-failed: state 'failed'" in manifest["problems"]


def test_missing_scheduled_run_is_a_problem(session):
    schedule = json.loads((session / "attacker" / "schedule.json").read_text())
    write_json(session / "attacker" / "schedule.json", {**schedule, "runs": [SYN_PLAN, UDP_PLAN, SYN_PLAN]})
    manifest, _ = run_export(session)
    assert "run inventory: 2 complete runs, schedule has 3" in manifest["problems"]


def test_schedule_for_another_session_is_a_problem(session):
    schedule = json.loads((session / "attacker" / "schedule.json").read_text())
    write_json(session / "attacker" / "schedule.json", {**schedule, "session_id": "policy-validation-2030-01-15-b"})
    manifest, _ = run_export(session)
    assert manifest["valid_for_scoring"] is False
    assert any("not 'policy-calibration-2030-01-15-a'" in p for p in manifest["problems"])


@pytest.mark.parametrize("edit, message", [
    (lambda meta, rows: (meta | {"summary": {"attempted": len(rows), "sent": len(rows) - 1}}, rows),
     "summary sent="),
    (lambda meta, rows: (meta | {"summary": {"attempted": len(rows) + 5, "sent": len(rows)}}, rows),
     "summary attempted="),
    (lambda meta, rows: (meta, [rows[0] | {"run_id": "other"}] + rows[1:]), "different run_id"),
    (lambda meta, rows: (meta, [rows[0]] + [rows[1] | {"packet_index": rows[0]["packet_index"]}] + rows[2:]),
     "duplicate packet_index"),
])
def test_attack_log_reconciliation_failures(session, edit, message):
    folder = session / "attacker" / "scenarios" / "a-syn"
    meta, rows = edit(json.loads((folder / "run.json").read_text()), lse.read_csv(folder / "activity.csv"))
    write_json(folder / "run.json", meta)
    write_csv(folder / "activity.csv", list(rows[0]), rows)
    manifest, _ = run_export(session)
    assert manifest["valid_for_scoring"] is False
    assert any(message in p for p in manifest["problems"]), manifest["problems"]


def test_client_settings_must_match_the_schedule(session):
    schedule = json.loads((session / "attacker" / "schedule.json").read_text())
    write_json(session / "attacker" / "schedule.json", {**schedule, "client": {"rate": 20, "duration": 55}})
    manifest, _ = run_export(session)
    assert "client run: rate 10 differs from schedule 20" in manifest["problems"]
    assert manifest["client_run"]["rate"] == 10


def test_lost_packets_are_a_problem(session):
    kept = [item for index, item in enumerate(PACKETS[session]) if index != 1651]  # one UDP packet (at 35 s)
    write_pcap(session / "server.pcap", kept)
    manifest, _ = run_export(session)
    assert [r["sent_equals_captured"] for r in manifest["attack_runs"]] == [True, False]
    assert manifest["valid_for_scoring"] is False


@pytest.mark.parametrize("dropped, message", [(None, "drop count not recorded"), (3, "3 packets dropped")])
def test_kernel_drops_fail_closed(session, dropped, message):
    manifest, _ = run_export(session, tcpdump_dropped=dropped)
    assert manifest["valid_for_scoring"] is False and any(message in p for p in manifest["problems"])


def test_zero_drops_alone_do_not_certify_a_session(session):
    manifest, _ = run_export(session, clock_before=None, clock_after=None)
    assert manifest["valid_for_scoring"] is False
    assert "clock evidence missing: no before-session clock file" in manifest["problems"]


def test_clock_shift_moves_run_boundaries(session):
    clock_file(session / "fast-before.json", attacker=3.0)  # attacker clock 3 s ahead of the server
    clock_file(session / "fast-after.json", attacker=3.0)
    manifest, rows = run_export(session, clock_before=session / "fast-before.json",
                                clock_after=session / "fast-after.json")
    assert manifest["clock"]["attacker"]["shift_used"] == -3.0
    assert rows[19]["exclusion_reason"] == "run start/stop boundary"  # 25 - 3 = 22 boundary covers 19..24
    assert rows[16]["label"] == "attack"  # run now 12-22 s
    assert rows[9]["exclusion_reason"] == "run start/stop boundary"


def test_drift_widens_boundaries_and_too_much_drift_fails(session):
    clock_file(session / "d-before.json", attacker=0.0)
    clock_file(session / "d-after.json", attacker=1.0)
    manifest, rows = run_export(session, clock_before=session / "d-before.json", clock_after=session / "d-after.json")
    assert manifest["clock"]["attacker"]["uncertainty"] == pytest.approx(0.52)
    assert manifest["settings"]["boundary_seconds"] == pytest.approx(3.02)
    clock_file(session / "e-after.json", attacker=6.0)
    manifest, _ = run_export(session, out="out2", clock_before=session / "d-before.json",
                             clock_after=session / "e-after.json")
    assert manifest["valid_for_scoring"] is False
    assert any("attacker clock uncertainty" in p for p in manifest["problems"])


def test_refuses_to_overwrite_an_export(session):
    run_export(session)
    with pytest.raises(FileExistsError):
        run_export(session)


def test_scores_only_valid_sessions(session, monkeypatch):
    from ddos_detector import training
    monkeypatch.setattr(training, "load_model", lambda _: ("pipe", {"model_sha256": "m", "decision_threshold": 0.5}))
    monkeypatch.setattr(training, "score_loaded_record",
                        lambda pipe, meta, record: {"attack_score": record["features"]["packet_rate"] / 1000})
    _, rows = run_export(session, model="model-dir")
    assert rows[19]["score"] == {"attack_score": 0.11}
    manifest, rows = run_export(session, out="out2", tcpdump_dropped=3, model="model-dir")
    assert manifest["valid_for_scoring"] is False
    assert all(row["score"] is None for row in rows.values())


def test_reads_real_http_client_and_scenario_exports(tmp_path, monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        http_client.run_requests(client, http_client.ClientSettings("http://10.10.10.10/"),
                                 http_client.RunSettings(5, 0.5), export=http_client.RunExport(tmp_path / "c"))
    run_dir = next((tmp_path / "c").iterdir())
    problems = []
    client = lse.load_client_run(run_dir, 0.0, {"rate": 5, "duration": 0.5}, problems)
    assert client["rate"] == 5 and client["duration"] == 0.5 and client["state"] == "complete"
    assert problems == []

    # Exercise the real export format without requiring this host to build/send
    # its first packet inside a one-second wall-clock deadline.
    class Clock:
        now = 0.0
        def sleep(self, duration):
            self.now += duration
    clock = Clock()
    monkeypatch.setattr(scenarios, "perf_counter", lambda: clock.now)
    monkeypatch.setattr(scenarios, "sleep", clock.sleep)
    settings = scenarios.ScenarioSettings(protocol="udp", port=9999, rate=5, duration=1)
    scenarios.run_scenario(settings, NullSender(), scenarios.ScenarioExport(tmp_path / "s", settings))
    runs, retained = lse.load_attack_runs(tmp_path / "s", 0.0, problems)
    assert len(runs) == 1 and retained == [] and problems == []
    lse.check_inventory(runs, {"runs": [{"protocol": "udp", "port": 9999, "rate": 5, "duration": 1}]}, problems)
    assert problems == []


def test_clock_check_bounds_the_offset():
    script = "import sys, time\nfor _ in sys.stdin:\n    print(f'{time.time() + 5:.6f}', flush=True)\n"
    result = lab_clock_check.measure([sys.executable, "-c", script], samples=5)
    assert abs(result["offset_seconds"] - 5.0) <= result["bound_seconds"] + 0.000001
    assert result["bound_seconds"] >= 0 and result["samples"] == 5


def test_capture_that_stops_early_is_a_problem(session):
    write_pcap(session / "server.pcap", [item for item in PACKETS[session] if item[0] < T0 + 40])
    manifest, _ = run_export(session)
    assert "capture does not cover the client run" in manifest["problems"]
    assert "capture does not cover the attack run b-udp" in manifest["problems"]


@pytest.mark.parametrize("case", ["missing_epoch", "same_file", "before_inside", "after_before_end", "swapped", "negative_bound"])
def test_clock_evidence_must_be_timestamped_and_bracket_capture(session, case):
    before, after = session / "clock-before.json", session / "clock-after.json"
    if case == "same_file":
        after = before
    elif case == "swapped":
        before, after = after, before
    else:
        path = after if case == "after_before_end" else before
        data = json.loads(path.read_text())
        for sample in data["vms"].values():
            if case == "missing_epoch":
                sample.pop("host_epoch")
            elif case == "before_inside":
                sample["host_epoch"] = T0 + 1
            elif case == "after_before_end":
                sample["host_epoch"] = T0 + 20
            elif case == "negative_bound":
                sample["bound_seconds"] = -1
        write_json(path, data)
    manifest, rows = run_export(session, clock_before=before, clock_after=after)
    assert manifest["valid_for_scoring"] is False and manifest["problems"]
    assert not any(row["eligible_for_policy"] for row in rows.values())
    assert all(row["score"] is None for row in rows.values())


def test_clock_command_creates_the_documented_session_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_clock_check, "check", lambda **_: {"vms": {"server": {"offset_seconds": 0}}})
    output = tmp_path / "fresh-session" / "clock-before.json"
    lab_clock_check.main(["--out", str(output)])
    assert json.loads(output.read_text())["vms"]["server"]["offset_seconds"] == 0


@pytest.mark.parametrize("samples", [0, -1])
def test_clock_measure_rejects_empty_sample_sets(samples):
    with pytest.raises(ValueError, match="positive integer"):
        lab_clock_check.measure(["must-not-run"], samples=samples)


@pytest.mark.parametrize("slack", [-1, float("inf"), float("nan")])
def test_invalid_slack_is_rejected_before_writing(session, slack):
    with pytest.raises(ValueError, match="slack"):
        run_export(session, slack=slack)
    assert not (session / "out").exists()
