"""Offline tests only: no SYN or UDP packets are sent by this suite."""

import csv
import json

import pytest
from scapy.all import IP, TCP, UDP

from ddos_detector import scenarios


@pytest.mark.parametrize("changes", [
    {"protocol": "icmp"}, {"target": "example.com"}, {"target": "10.10.10.20"},
    {"rate": 0}, {"rate": 1001}, {"rate": float("nan")},
    {"duration": 0}, {"duration": 61}, {"duration": float("inf")},
    {"rate": 1000, "duration": 11}, {"port": 0}, {"port": 65536},
    {"port": True}, {"interface": ""},
])
def test_reject_invalid_or_unbounded_settings(changes):
    with pytest.raises(ValueError):
        scenarios.ScenarioSettings(**{"protocol": "syn", **changes})


@pytest.mark.parametrize("protocol", ["syn", "udp"])
def test_packet_bytes_have_real_lab_source_and_requested_protocol(protocol):
    settings = scenarios.ScenarioSettings(protocol, port=9999)
    packet = IP(bytes(scenarios.build_packet(settings, 2)))
    assert packet.src == "10.10.10.30"
    assert packet.dst == "10.10.10.10"
    transport = packet[TCP] if protocol == "syn" else packet[UDP]
    assert transport.dport == 9999
    assert transport.sport == 49153
    if protocol == "syn":
        assert int(transport.flags) == 2
    else:
        assert bytes(transport.payload) == b"COMP3670 lab scenario"


@pytest.fixture
def clock(monkeypatch):
    class Clock:
        now = 0.0

        def sleep(self, seconds):
            self.now += seconds

    clock = Clock()
    monkeypatch.setattr(scenarios, "perf_counter", lambda: clock.now)
    monkeypatch.setattr(scenarios, "sleep", clock.sleep)
    return clock


def execute(tmp_path, settings, send):
    class Sender:
        def send(self, packet):
            send(packet)

    export = scenarios.ScenarioExport(tmp_path, settings)
    try:
        state, summary = scenarios.run_scenario(settings, Sender(), export)
    finally:
        export.close()
    metadata = json.loads((export.directory / "run.json").read_text())
    with (export.directory / "activity.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert metadata["state"] == state
    assert metadata["summary"] == summary
    assert len(rows) == summary["attempted"]
    assert len({row["packet_index"] for row in rows}) == len(rows)
    assert all(row["run_id"] == export.run_id for row in rows)
    assert summary["scheduled_slots"] == (
        summary["attempted"] + summary["skipped_due_to_lag"] + summary["cancelled_slots"]
    )
    return state, summary, rows


@pytest.mark.parametrize("protocol", ["syn", "udp"])
def test_repeatable_fixed_grid_and_export(tmp_path, clock, protocol):
    starts = []
    state, summary, rows = execute(
        tmp_path, scenarios.ScenarioSettings(protocol, rate=2, duration=2),
        lambda packet: starts.append(clock.now),
    )
    assert starts == [0, .5, 1, 1.5]
    assert state == "complete"
    assert summary["sent"] == 4
    assert summary["elapsed_seconds"] == 2
    assert summary["achieved_packets_per_second"] == 2
    assert summary["skipped_due_to_lag"] == 0
    assert [int(row["packet_index"]) for row in rows] == [1, 2, 3, 4]
    from datetime import datetime
    assert all(float(row["epoch_seconds"]) == datetime.fromisoformat(row["started_at"]).timestamp() for row in rows)


def test_slow_send_accounts_for_tail_without_replay(tmp_path, clock):
    def send(packet):
        clock.now += 3

    _, summary, _ = execute(tmp_path, scenarios.ScenarioSettings("syn", rate=2, duration=2), send)
    assert summary["sent"] == 1
    assert summary["skipped_due_to_lag"] == 3


def test_oversleep_skips_without_catch_up(tmp_path, clock, monkeypatch):
    monkeypatch.setattr(scenarios, "sleep", lambda seconds: setattr(clock, "now", clock.now + seconds + 1))
    starts = []
    _, summary, rows = execute(tmp_path, scenarios.ScenarioSettings("udp", rate=2, duration=2), lambda packet: starts.append(clock.now))
    assert starts == [0, 1.5]
    assert [int(row["packet_index"]) for row in rows] == [1, 4]
    assert summary["skipped_due_to_lag"] == 2


def test_interrupt_during_send_records_uncertainty_and_stops(tmp_path, clock):
    def send(packet):
        raise KeyboardInterrupt

    state, summary, rows = execute(tmp_path, scenarios.ScenarioSettings("syn", rate=2, duration=2), send)
    assert state == "interrupted"
    assert summary["unknown"] == 1
    assert summary["sent"] == 0
    assert summary["cancelled_slots"] == 3
    assert rows[0]["outcome"] == "interrupted_unknown"


def test_interrupt_between_collection_and_csv_write_recovers_row(tmp_path, clock, monkeypatch):
    def record(self, row):
        raise KeyboardInterrupt

    monkeypatch.setattr(scenarios.ScenarioExport, "record", record)
    state, summary, rows = execute(tmp_path, scenarios.ScenarioSettings("udp", rate=2, duration=2), lambda packet: None)
    assert state == "interrupted"
    assert summary["sent"] == 1
    assert summary["cancelled_slots"] == 3
    assert rows[0]["outcome"] == "sent"


def test_send_failure_cancels_remaining_work(tmp_path, clock):
    def send(packet):
        raise OSError("socket failed")

    state, summary, rows = execute(tmp_path, scenarios.ScenarioSettings("udp", rate=2, duration=2), send)
    assert state == "failed"
    assert summary["send_errors"] == 1
    assert summary["cancelled_slots"] == 3
    assert rows[0]["error_type"] == "OSError"


def test_plan_does_not_open_network_or_create_exports(tmp_path, monkeypatch, capsys):
    def forbidden(*args):
        pytest.fail("plan attempted to open a live sender")

    monkeypatch.setattr(scenarios, "open_lab_sender", forbidden)
    assert scenarios.main(["--protocol", "syn", "--output", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "plan_only"
    assert list(tmp_path.iterdir()) == []


def test_export_setup_failure_prevents_sending(tmp_path, monkeypatch):
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    monkeypatch.setattr(scenarios, "open_lab_sender", lambda settings: pytest.fail("sent without an export"))
    with pytest.raises(SystemExit) as error:
        scenarios.main(["--protocol", "udp", "--execute", "--output", str(blocked)])
    assert error.value.code == 2


@pytest.mark.parametrize("protocol", ["syn", "udp"])
@pytest.mark.parametrize("failure", [
    ValueError("bad interface"), ValueError("no ARP response"),
    PermissionError("socket permission denied"), RuntimeError("socket setup failed"),
    KeyboardInterrupt(),
])
def test_setup_failure_saves_terminal_zero_attempt_record(tmp_path, monkeypatch, capsys, protocol, failure):
    def fail_setup(settings):
        raise failure

    monkeypatch.setattr(scenarios, "open_lab_sender", fail_setup)
    monkeypatch.setattr(scenarios, "run_scenario", lambda *args: pytest.fail("scenario started after setup failure"))
    arguments = ["--protocol", protocol, "--rate", "10", "--duration", "5",
                 "--execute", "--output", str(tmp_path)]
    interrupted = isinstance(failure, KeyboardInterrupt)
    if interrupted:
        assert scenarios.main(arguments) == 130
    else:
        with pytest.raises(SystemExit) as error:
            scenarios.main(arguments)
        assert error.value.code == 2
    directory, = tmp_path.iterdir()
    metadata = json.loads((directory / "run.json").read_text())
    from datetime import datetime
    assert datetime.fromisoformat(metadata["stopped_at"]).utcoffset().total_seconds() == 0
    assert metadata["started_at"] is None
    assert metadata["state"] == ("interrupted" if interrupted else "failed")
    assert metadata["error"]["phase"] == "setup"
    assert metadata["error"]["type"] == type(failure).__name__
    assert metadata["error"]["message"]
    summary = metadata["summary"]
    assert summary["scheduled_slots"] == summary["cancelled_slots"] == 50
    assert all(summary[name] == 0 for name in (
        "attempted", "sent", "send_errors", "unknown", "skipped_due_to_lag",
        "elapsed_seconds", "achieved_packets_per_second",
    ))
    assert summary["interrupted"] is interrupted
    with (directory / "activity.csv").open(newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == metadata["state"]
    assert report["summary"] == summary
    assert report["export_directory"] == str(directory.resolve())


def test_setup_record_write_failure_remains_incomplete(tmp_path, monkeypatch):
    def fail_setup(settings):
        raise ValueError("no ARP response")

    original_replace = scenarios.Path.replace

    def fail_reconciliation(path, target):
        if path.name == "activity.csv.tmp":
            raise OSError("disk failure")
        return original_replace(path, target)

    monkeypatch.setattr(scenarios, "open_lab_sender", fail_setup)
    monkeypatch.setattr(scenarios.Path, "replace", fail_reconciliation)
    with pytest.raises(SystemExit) as error:
        scenarios.main(["--protocol", "syn", "--execute", "--output", str(tmp_path)])
    assert error.value.code == 2
    directory, = tmp_path.iterdir()
    metadata = json.loads((directory / "run.json").read_text())
    assert metadata["state"] == "running"
    assert metadata["summary"] is None


def test_export_failure_after_start_never_relabels_run_as_zero_attempts(tmp_path, monkeypatch):
    class Sender:
        closed = False

        def close(self):
            self.closed = True

    sender = Sender()

    def fail_after_start(settings, sender, export):
        export.metadata["started_at"] = scenarios.utc_now()
        export.write_metadata()
        export.record({"packet_index": 1, "outcome": "sent"})
        raise OSError("export interrupted after sending")

    monkeypatch.setattr(scenarios, "open_lab_sender", lambda settings: sender)
    monkeypatch.setattr(scenarios, "run_scenario", fail_after_start)
    with pytest.raises(SystemExit) as error:
        scenarios.main(["--protocol", "udp", "--execute", "--output", str(tmp_path)])
    assert error.value.code == 2
    assert sender.closed
    directory, = tmp_path.iterdir()
    metadata = json.loads((directory / "run.json").read_text())
    assert metadata["state"] == "running"
    assert metadata["started_at"] is not None
    assert metadata["summary"] is None
    with (directory / "activity.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1
    assert rows[0]["outcome"] == "sent"


def test_failed_csv_finalization_leaves_metadata_incomplete(tmp_path, clock, monkeypatch):
    export = scenarios.ScenarioExport(tmp_path, scenarios.ScenarioSettings("syn"))
    original_replace = scenarios.Path.replace

    def fail_replace(path, target):
        if path.name == "activity.csv.tmp":
            raise OSError("failed replacement")
        return original_replace(path, target)

    monkeypatch.setattr(scenarios.Path, "replace", fail_replace)
    try:
        with pytest.raises(OSError, match="failed replacement"):
            export.finish([], {"attempted": 0}, "complete")
    finally:
        export.close()
    metadata = json.loads((export.directory / "run.json").read_text())
    assert metadata["state"] == "running"
    assert metadata["summary"] is None


def test_live_mode_rejects_windows_before_network(monkeypatch):
    monkeypatch.setattr(scenarios.platform, "system", lambda: "Windows")
    with pytest.raises(ValueError, match="Linux"):
        scenarios.open_lab_sender(scenarios.ScenarioSettings("syn"))


@pytest.mark.parametrize("route", [
    ("enp0s3", "10.10.10.30", "0.0.0.0"),
    ("enp0s8", "10.10.10.20", "0.0.0.0"),
    ("enp0s8", "10.10.10.30", "10.0.2.2"),
])
def test_bad_route_rejected_before_arp_or_socket(monkeypatch, route):
    import scapy.all as scapy

    monkeypatch.setattr(scenarios.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scapy.conf.route, "route", lambda target: route)
    monkeypatch.setattr(scapy, "get_if_addr", lambda interface: "10.10.10.30")
    monkeypatch.setattr(scapy, "getmacbyip", lambda target: pytest.fail("ARP on invalid route"))
    with pytest.raises(ValueError, match="direct lab route"):
        scenarios.open_lab_sender(scenarios.ScenarioSettings("syn"))


def test_live_sender_uses_validated_interface_and_closes_socket(monkeypatch):
    import scapy.all as scapy

    sent = []

    class Socket:
        closed = False

        def send(self, packet):
            sent.append(packet)
            return len(bytes(packet))

        def close(self):
            self.closed = True

    socket = Socket()
    monkeypatch.setattr(scenarios.platform, "system", lambda: "Linux")
    monkeypatch.setattr(scapy.conf.route, "route", lambda target: ("enp0s8", "10.10.10.30", "0.0.0.0"))
    monkeypatch.setattr(scapy, "get_if_addr", lambda interface: "10.10.10.30")
    monkeypatch.setattr(scapy, "get_if_hwaddr", lambda interface: "02:00:00:00:00:30")
    monkeypatch.setattr(scapy, "getmacbyip", lambda target: "02:00:00:00:00:10")
    interfaces = []
    monkeypatch.setattr(scapy.conf, "L2socket", lambda iface: (interfaces.append(iface), socket)[1])
    settings = scenarios.ScenarioSettings("syn")
    sender = scenarios.open_lab_sender(settings)
    sender.send(scenarios.build_packet(settings, 1))
    sender.close()
    assert interfaces == ["enp0s8"]
    assert sent[0][scapy.Ether].dst == "02:00:00:00:00:10"
    assert socket.closed
