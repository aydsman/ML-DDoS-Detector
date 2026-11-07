"""Collector regressions using real HTTP-export code and a mocked transport."""
import csv
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest

from ddos_detector import http_client
from ddos_detector.http_client import ClientSettings, RunSettings
from tools import collect_baseline as collector


@pytest.fixture
def controlled(monkeypatch):
    clock = [0.0]
    requests = []
    outcomes = []
    original_client = httpx.Client

    def respond(request):
        requests.append(request)
        outcome = outcomes.pop(0) if outcomes else 200
        if isinstance(outcome, BaseException):
            raise outcome
        return httpx.Response(outcome)

    def client(**kwargs):
        assert kwargs == {"trust_env": False}
        return original_client(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(collector.httpx, "Client", client)
    monkeypatch.setattr(http_client, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(http_client, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(collector, "code_provenance", lambda: {
        "git_commit": "a" * 40, "git_dirty": True, "unavailable_reason": None})
    monkeypatch.setattr(collector, "environment_snapshot", lambda: {
        "os": "test guest", "python_version": "3.12.15",
        "installed_distributions": [{"name": "httpx", "version": httpx.__version__}]})
    snapshots = Mock(side_effect=lambda: {
        "scope": "collector_os_visible", "cpu_logical_count": 2,
        "memory_bytes": 2 * 1024**3, "observed_at": collector.utc_now()})
    monkeypatch.setattr(collector, "machine_resources", snapshots)
    return requests, outcomes, snapshots


def read_collection(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_export(path, trial):
    directory = path.parent / trial["export_directory"]
    metadata = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    with (directory / "requests.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return metadata, rows


def test_repeated_trials_keep_real_exports_failures_and_provenance(tmp_path, controlled):
    requests, outcomes, snapshots = controlled
    outcomes.extend([200, 503, httpx.ReadTimeout("mock timeout")])
    path = collector.collect_baselines(tmp_path, ClientSettings("http://127.0.0.1/"),
                                       RunSettings(1, 1), repetitions=3)
    manifest = read_collection(path)
    assert manifest["status"] == "complete"
    assert manifest["evidence_kind"] == "local_smoke"
    assert manifest["acceptance"]["comparable_baseline"] is False
    assert manifest["resource_record"]["status"] == "missing"
    assert manifest["code"]["git_commit"] == "a" * 40
    assert manifest["code"]["git_dirty"] is True
    assert manifest["environment"]["installed_distributions"]
    assert manifest["started_at"].endswith("Z") and manifest["ended_at"].endswith("Z")
    assert len(requests) == snapshots.call_count == len(manifest["trials"]) == 3
    assert len({t["run_id"] for t in manifest["trials"]}) == 3
    assert [t["summary"]["successful_2xx"] for t in manifest["trials"]] == [1, 0, 0]
    for trial, expected_outcome in zip(manifest["trials"], ["http_response", "http_response", "timeout"]):
        metadata, rows = read_export(path, trial)
        assert metadata["run_id"] == trial["run_id"]
        assert metadata["state"] == trial["status"] == "complete"
        assert len(rows) == metadata["summary"]["attempted"] == trial["summary"]["attempted"] == 1
        assert rows[0]["outcome"] == expected_outcome
        assert trial["resources"]["scope"] == "collector_os_visible"
        for filename, artifact in trial["artifacts"].items():
            saved = path.parent / trial["export_directory"] / filename
            assert artifact["sha256"] == hashlib.sha256(saved.read_bytes()).hexdigest()


def test_lab_target_is_candidate_and_resource_record_is_copied_not_approved(tmp_path, controlled):
    resource = tmp_path / "allocation.json"
    resource.write_text('{"client_vcpu":2,"unverified":true}', encoding="utf-8")
    path = collector.collect_baselines(tmp_path / "output", ClientSettings("http://10.10.10.10/"),
                                       RunSettings(1, 1), 1, resource)
    manifest = read_collection(path)
    saved = manifest["resource_record"]
    assert (path.parent / saved["path"]).read_bytes() == resource.read_bytes()
    assert saved["sha256"] == hashlib.sha256(resource.read_bytes()).hexdigest()
    assert saved["status"] == "supplied_unreviewed"
    assert manifest["evidence_kind"] == "lab_baseline_candidate"
    assert manifest["acceptance"]["status"] == "pending_review"
    assert manifest["acceptance"]["comparable_baseline"] is False


def test_interrupted_http_attempt_is_finalized_and_stops_repetitions(tmp_path, controlled):
    requests, outcomes, snapshots = controlled
    outcomes.append(KeyboardInterrupt())
    path = collector.collect_baselines(tmp_path, ClientSettings("http://localhost/"),
                                       RunSettings(1, 10), 3)
    manifest = read_collection(path)
    assert manifest["status"] == "interrupted"
    assert len(manifest["trials"]) == len(requests) == snapshots.call_count == 1
    metadata, rows = read_export(path, manifest["trials"][0])
    assert metadata["state"] == "interrupted"
    assert metadata["summary"]["attempted"] == len(rows) == 1
    assert rows[0]["outcome"] == "interrupted"


def test_error_after_completed_trial_preserves_both_known_runs(tmp_path, controlled, monkeypatch):
    original = collector.run_requests
    calls = [0]

    def fail_second(client, settings, run, export):
        calls[0] += 1
        if calls[0] == 1:
            return original(client, settings, run, export=export)
        export.begin(settings, run, "00000000-0000-0000-0000-000000000002", collector.utc_now())
        raise OSError("simulated export failure")

    monkeypatch.setattr(collector, "run_requests", fail_second)
    path = collector.collect_baselines(tmp_path, ClientSettings("http://localhost/"), RunSettings(1, 1), 3)
    manifest = read_collection(path)
    assert manifest["status"] == "partial"
    assert [t["status"] for t in manifest["trials"]] == ["complete", "error"]
    assert manifest["trials"][1]["summary"] is None
    assert "OSError" in manifest["trials"][1]["error"]
    assert read_export(path, manifest["trials"][0])[1][0]["status_code"] == "200"
    metadata, rows = read_export(path, manifest["trials"][1])
    assert metadata["state"] == "running" and metadata["summary"] is None and rows == []


def test_interrupt_outside_http_runner_retains_partial_export(tmp_path, controlled, monkeypatch):
    def interrupt(client, settings, run, export):
        export.begin(settings, run, "00000000-0000-0000-0000-000000000003", collector.utc_now())
        raise KeyboardInterrupt

    monkeypatch.setattr(collector, "run_requests", interrupt)
    path = collector.collect_baselines(tmp_path, ClientSettings("http://localhost/"), RunSettings(1, 1), 3)
    manifest = read_collection(path)
    assert manifest["status"] == "interrupted"
    assert len(manifest["trials"]) == 1 and manifest["trials"][0]["summary"] is None
    metadata, rows = read_export(path, manifest["trials"][0])
    assert metadata["state"] == "running" and rows == []


@pytest.mark.parametrize("repetitions", [0, -1, 1.5, True])
def test_invalid_repetitions_do_not_create_outputs_or_send(tmp_path, controlled, repetitions):
    with pytest.raises(ValueError, match="positive integer"):
        collector.collect_baselines(tmp_path / "output", ClientSettings("http://localhost/"),
                                    RunSettings(1, 1), repetitions)
    assert not (tmp_path / "output").exists() and not controlled[0]


@pytest.mark.parametrize("option,value", [("--duration", "0"), ("--duration", "nan"),
                                         ("--rate", "inf"), ("--rate", "101"),
                                         ("--timeout", "-1"), ("--concurrency", "33"),
                                         ("--target", "http://example.com/")])
def test_invalid_cli_settings_never_send(tmp_path, controlled, option, value):
    with pytest.raises(SystemExit) as exc:
        collector.main(["--output", str(tmp_path / "output"), option, value])
    assert exc.value.code == 2
    assert not (tmp_path / "output").exists() and not controlled[0]


def test_missing_resource_record_fails_before_collection(tmp_path, controlled):
    with pytest.raises(ValueError, match="existing file"):
        collector.collect_baselines(tmp_path / "output", ClientSettings("http://localhost/"),
                                    RunSettings(1, 1), 1, tmp_path / "missing.json")
    assert not (tmp_path / "output").exists() and not controlled[0]


def test_collection_uuid_collision_does_not_overwrite(tmp_path, controlled, monkeypatch):
    monkeypatch.setattr(collector, "uuid4", lambda: "00000000-0000-0000-0000-000000000001")
    path = collector.collect_baselines(tmp_path, ClientSettings("http://localhost/"), RunSettings(1, 1), 1)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        collector.collect_baselines(tmp_path, ClientSettings("http://localhost/"), RunSettings(1, 1), 1)
    assert path.read_bytes() == original and len(controlled[0]) == 1


@pytest.mark.parametrize("outcome,expected", [(200, 0), (503, 1), (KeyboardInterrupt(), 130)])
def test_cli_reports_manifest_and_outcome_exit_code(tmp_path, controlled, capsys, outcome, expected):
    controlled[1].append(outcome)
    assert collector.main(["--output", str(tmp_path), "--target", "http://localhost/",
                           "--rate", "1", "--duration", "1", "--repetitions", "1"]) == expected
    report = json.loads(capsys.readouterr().out)
    assert Path(report["manifest"]).is_file()
    assert report["evidence_kind"] == "local_smoke"
    assert report["status"] == ("interrupted" if expected == 130 else "complete")


def test_unknown_resources_are_null_not_invented(monkeypatch):
    monkeypatch.setattr(collector.platform, "system", lambda: "Linux")
    monkeypatch.setattr(collector.os, "cpu_count", lambda: None)
    monkeypatch.setattr(collector.os, "sysconf", Mock(side_effect=ValueError("not supported")), raising=False)
    observed = collector.machine_resources()
    assert observed["cpu_logical_count"] is None and observed["memory_bytes"] is None
    assert "cpu_logical_count" in observed["unavailable_reason"]
    assert "memory_bytes" in observed["unavailable_reason"]
