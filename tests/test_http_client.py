import csv
import json
import subprocess
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from time import sleep

import httpx
import pytest

from ddos_detector.http_client import (
    ClientSettings, RequestResult, RunExport, RunResult, RunSettings, export_run,
    run_requests, send_request,
)
import ddos_detector.http_client as http_client


@pytest.mark.parametrize("target", ["localhost:8000", "ftp://localhost/", "http://", "http://user:password@localhost/"])
def test_invalid_target_is_rejected(target):
    with pytest.raises(ValueError):
        ClientSettings(target)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_timeout_is_rejected(timeout):
    with pytest.raises(ValueError):
        ClientSettings("http://127.0.0.1/", timeout)


@pytest.mark.parametrize("status", [200, 404, 503])
def test_http_errors_are_still_measured_responses(status):
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(status))) as client:
        result = send_request(client, ClientSettings("http://localhost/"))
    assert result.outcome == "http_response"
    assert result.status_code == status
    assert result.error_type is None
    assert result.elapsed_ms >= 0
    assert datetime.fromisoformat(result.started_at).utcoffset().total_seconds() == 0
    assert result.epoch_seconds == datetime.fromisoformat(result.started_at).timestamp()


@pytest.mark.parametrize("exception,outcome", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectError, "request_error")])
def test_transport_failures_produce_results(exception, outcome):
    def fail(request):
        raise exception("Controlled test failure", request=request)

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        result = send_request(client, ClientSettings("http://localhost/"))
    assert result.outcome == outcome
    assert result.status_code is None
    assert result.error_type == exception.__name__
    assert result.elapsed_ms >= 0


def test_real_request_to_local_server(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"Local HTTP client test"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = ClientSettings(f"http://127.0.0.1:{server.server_port}/")
            with httpx.Client(trust_env=False) as client:
                result = send_request(client, settings)
            assert result.outcome == "http_response"
            assert result.status_code == 200
            command = subprocess.run([
                sys.executable, "-m", "ddos_detector.http_client",
                "--target", settings.target, "--timeout", "2",
                "--rate", "5", "--duration", "0.3", "--output", str(tmp_path),
                "--concurrency", "2",
            ], capture_output=True, text=True, timeout=15)
            assert command.returncode == 0, command.stderr
            report = json.loads(command.stdout)
            run_dir = Path(report["export_directory"])
            metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            with (run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            assert len(rows) == report["result"]["attempted"] > 0
            assert metadata["summary"]["successful_2xx"] == len(rows)
            assert metadata["settings"]["concurrency"] == 2
            assert all(row["status_code"] == "200" for row in rows)
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf")])
def test_invalid_run_settings_are_rejected(value):
    with pytest.raises(ValueError):
        RunSettings(value, 1)
    with pytest.raises(ValueError):
        RunSettings(1, value)


@pytest.mark.parametrize("response_seconds,expected_starts", [
    (0.05, [0, 0.5, 1, 1.5]),
    (0.75, [0, 0.75, 1.5]),
])
def test_run_pacing_deadline_and_achieved_rate(monkeypatch, response_seconds, expected_starts):
    # Virtual time tests slow responses without flaky real-time assertions.
    clock = [0.0]
    starts = []

    def advance(seconds):
        clock[0] += seconds

    def respond(request):
        starts.append(clock[0])
        advance(response_seconds)
        return httpx.Response(200)

    monkeypatch.setattr(http_client, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(http_client, "sleep", advance)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2))
    assert starts == expected_starts
    assert all(start < 2 for start in starts)
    assert result.attempted == len(starts)
    assert result.successful_2xx == len(starts)
    assert result.elapsed_seconds == max(2, starts[-1] + response_seconds)
    assert result.achieved_requests_per_second == len(starts) / result.elapsed_seconds
    assert [item.elapsed_ms for item in result.requests] == pytest.approx(
        [response_seconds * 1000] * len(starts)
    )


def test_exports_preserve_settings_failures_and_run_identity(tmp_path):
    timestamp = "2026-10-27T23:00:00Z"
    requests = [
        RequestResult(timestamp, 10.5, "http_response", 200, None),
        RequestResult(timestamp, 20.0, "http_response", 503, None),
        RequestResult(timestamp, 500, "timeout", None, "ReadTimeout"),
        RequestResult(timestamp, 30, "request_error", None, "ConnectError"),
    ]
    result = RunResult(
        timestamp, 2, 2, 4, 1, requests,
        skipped_due_to_capacity=3, skipped_at_deadline=1,
    )
    settings = ClientSettings("http://127.0.0.1:8000/", 0.5)
    run = RunSettings(2, 2)
    run_dir = export_run(tmp_path, settings, run, result)
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    with (run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert metadata["run_id"] == run_dir.name == result.run_id
    assert metadata["schema_version"] == "draft-2"
    assert metadata["state"] == "complete"
    assert metadata["settings"] == {
        "target": settings.target, "timeout_seconds": 0.5,
        "request_rate": 2, "duration_seconds": 2, "concurrency": 1,
    }
    assert metadata["summary"]["attempted"] == len(rows) == 4
    assert metadata["summary"]["successful_2xx"] == 1
    assert metadata["summary"]["skipped_due_to_capacity"] == 3
    assert metadata["summary"]["skipped_at_deadline"] == 1
    assert metadata["summary"]["outcome_counts"] == {
        "http_response": 2, "timeout": 1, "request_error": 1,
    }
    assert all(row["run_id"] == result.run_id for row in rows)
    assert [row["request_index"] for row in rows] == ["1", "2", "3", "4"]
    assert rows[1]["status_code"] == "503"
    assert rows[2]["status_code"] == ""
    assert rows[2]["error_type"] == "ReadTimeout"
    assert float(rows[0]["elapsed_ms"]) == 10.5
    assert float(rows[0]["epoch_seconds"]) == datetime.fromisoformat(timestamp).timestamp()
    original_json = (run_dir / "run.json").read_bytes()
    with pytest.raises(FileExistsError):
        export_run(tmp_path, settings, run, result)
    assert (run_dir / "run.json").read_bytes() == original_json
    another = RunResult(timestamp, 2, 0, 0, 0, [])
    another_dir = export_run(tmp_path, settings, run, another)
    assert another_dir != run_dir
    with (another_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
        assert list(csv.DictReader(handle)) == []


def test_export_does_not_treat_run_id_as_arbitrary_path(tmp_path):
    result = RunResult("2026-10-27T23:00:00Z", 1, 0, 0, 0, [], run_id="../outside")
    with pytest.raises(ValueError):
        export_run(tmp_path, ClientSettings("http://localhost/"), RunSettings(1, 1), result)
    assert list(tmp_path.iterdir()) == []


def test_output_requires_run_options(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "http_client", "--target", "http://localhost/", "--output", "results",
    ])
    with pytest.raises(SystemExit) as exc:
        http_client.main()
    assert exc.value.code == 2
    assert "--output requires a paced run" in capsys.readouterr().err


@pytest.mark.parametrize("value", [0, -1, 33, 1.5, True])
def test_invalid_concurrency_is_rejected(value):
    with pytest.raises(ValueError):
        RunSettings(2, 1, value)


@pytest.mark.parametrize("exception,expected_outcome", [
    (httpx.ConnectError, "request_error"), (httpx.ReadTimeout, "timeout"),
])
def test_concurrent_run_overlaps_bounds_work_and_preserves_results(exception, expected_outcome):
    release = Event()
    two_started = Event()
    second_finished = Event()
    lock = Lock()
    state = {"active": 0, "peak": 0, "started": 0}
    outcome = {}

    def respond(request):
        with lock:
            state["active"] += 1
            state["started"] += 1
            index = state["started"]
            state["peak"] = max(state["peak"], state["active"])
            if state["active"] == 2:
                two_started.set()
        try:
            assert release.wait(timeout=5)
            if index == 1:
                assert second_finished.wait(timeout=5)
                raise exception("Controlled concurrent failure", request=request)
            second_finished.set()
            return httpx.Response(200)
        finally:
            with lock:
                state["active"] -= 1

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        def run():
            try:
                outcome["result"] = run_requests(
                    client, ClientSettings("http://localhost/"), RunSettings(20, 0.4, 2)
                )
            except BaseException as exc:
                outcome["error"] = exc

        thread = Thread(target=run, daemon=True)
        thread.start()
        try:
            assert two_started.wait(timeout=3), "Requests did not overlap"
            # Hold both workers through the start deadline. There must be no
            # queued requests that run after releasing these two responses.
            sleep(0.5)
        finally:
            release.set()
            thread.join(timeout=10)
        assert not thread.is_alive()
        if "error" in outcome:
            raise outcome["error"]
    result = outcome["result"]
    assert state["peak"] == state["started"] == result.attempted == 2
    assert result.skipped_due_to_capacity > 0
    assert result.elapsed_seconds >= 0.4
    assert result.successful_2xx == 1
    # Completion order was reversed, but records retain dispatch order.
    assert [item.outcome for item in result.requests] == [expected_outcome, "http_response"]
    assert result.requests[0].error_type == exception.__name__


def test_delayed_workers_do_not_send_after_deadline(monkeypatch):
    clock = [0.0]

    def advance(seconds):
        clock[0] += seconds

    class DelayedFuture:
        def __init__(self, action):
            self.action = action

        def done(self):
            return False

        def result(self):
            return self.action()

    class DelayedExecutor:
        def __init__(self, max_workers):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, action, *args):
            return DelayedFuture(lambda: action(*args))

    def unexpected_request(request):
        pytest.fail("A delayed worker sent a request after the deadline")

    monkeypatch.setattr(http_client, "ThreadPoolExecutor", DelayedExecutor)
    monkeypatch.setattr(http_client, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(http_client, "sleep", advance)
    with httpx.Client(transport=httpx.MockTransport(unexpected_request)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(10, 1, 2))
    assert result.attempted == 0
    assert result.skipped_at_deadline == 2
    assert result.skipped_due_to_capacity > 0


@pytest.mark.parametrize("target", [
    "http://example.com/", "http://10.10.10.30/", "http://localhost.example.com/",
    "http://127.0.0.1.example.com/", "http://10.10.10.10.example.com/",
])
def test_targets_outside_lab_and_loopback_are_rejected(target):
    with pytest.raises(ValueError, match="lab server"):
        ClientSettings(target)


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:8000/", "http://localhost/", "http://[::1]/", "http://10.10.10.10/",
])
def test_local_and_lab_targets_are_allowed(target):
    assert ClientSettings(target).target == target


def test_legitimate_rate_is_capped():
    assert RunSettings(100, 1).request_rate == 100
    with pytest.raises(ValueError, match="must not exceed"):
        RunSettings(1e6, 1, 32)


def test_fixed_grid_avoids_accumulated_wakeup_drift(monkeypatch):
    clock = [0.0]
    starts = []

    def late_sleep(seconds):
        clock[0] += seconds + 0.01

    def respond(request):
        starts.append(clock[0])
        return httpx.Response(200)

    monkeypatch.setattr(http_client, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(http_client, "sleep", late_sleep)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2))
    assert starts == pytest.approx([0, 0.51, 1.01, 1.51])
    assert result.skipped_due_to_lag == 0


def test_fixed_grid_skips_whole_missed_slots(monkeypatch):
    clock = [0.0]
    starts = []

    def advance(seconds):
        clock[0] += seconds

    def respond(request):
        starts.append(clock[0])
        advance(1.2)
        return httpx.Response(200)

    monkeypatch.setattr(http_client, "perf_counter", lambda: clock[0])
    monkeypatch.setattr(http_client, "sleep", advance)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2))
    assert starts == [0, 1.2]
    assert [item.request_index for item in result.requests] == [1, 3]
    assert result.skipped_due_to_lag == 2


def test_unexpected_request_error_is_recorded():
    def fail(request):
        raise RuntimeError("Unexpected adapter failure")

    with httpx.Client(transport=httpx.MockTransport(fail)) as client:
        result = send_request(client, ClientSettings("http://localhost/"))
    assert result.outcome == "unexpected_error"
    assert result.error_type == "RuntimeError"
    assert result.status_code is None


@pytest.mark.parametrize("concurrency", [1, 2])
def test_interrupt_while_waiting_preserves_flushed_results(tmp_path, monkeypatch, concurrency):
    sent = Event()

    def respond(request):
        sent.set()
        return httpx.Response(200)

    def interrupt(seconds):
        assert sent.wait(timeout=3)
        raise KeyboardInterrupt

    monkeypatch.setattr(http_client, "sleep", interrupt)
    export = RunExport(tmp_path)
    try:
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            result = run_requests(
                client, ClientSettings("http://localhost/"), RunSettings(1, 30, concurrency),
                export=export,
            )
    finally:
        export.close()
    assert result.interrupted
    assert result.attempted == 1
    metadata = json.loads((export.run_dir / "run.json").read_text(encoding="utf-8"))
    with (export.run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert metadata["state"] == "interrupted"
    assert metadata["summary"]["interrupted"]
    assert len(rows) == metadata["summary"]["attempted"] == 1


def test_interrupt_during_request_keeps_that_attempt(tmp_path):
    export = RunExport(tmp_path)

    def interrupt(request):
        raise KeyboardInterrupt

    try:
        with httpx.Client(transport=httpx.MockTransport(interrupt)) as client:
            result = run_requests(
                client, ClientSettings("http://localhost/"), RunSettings(1, 30), export=export,
            )
    finally:
        export.close()
    assert result.interrupted
    assert result.attempted == 1
    assert result.requests[0].outcome == "interrupted"
    assert result.requests[0].error_type == "KeyboardInterrupt"


def test_completed_rows_are_readable_before_run_finishes(tmp_path):
    export = RunExport(tmp_path)
    count = [0]

    def respond(request):
        count[0] += 1
        if count[0] == 2:
            with (export.run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            assert len(rows) == 1
            assert rows[0]["status_code"] == "200"
            # Simulate a process-level failure, not an ordinary HTTP error.
            raise SystemExit(99)
        return httpx.Response(200)

    try:
        with httpx.Client(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(SystemExit):
                run_requests(client, ClientSettings("http://localhost/"), RunSettings(20, 1), export=export)
    finally:
        export.close()
    metadata = json.loads((export.run_dir / "run.json").read_text(encoding="utf-8"))
    assert metadata["state"] == "running"
    assert metadata["summary"] is None
    with (export.run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
        assert len(list(csv.DictReader(handle))) == 1


def test_cli_interrupt_reports_saved_run_and_exit_code(tmp_path, monkeypatch, capsys):
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    def interrupt(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(http_client.httpx, "Client", lambda **kwargs: client)
    monkeypatch.setattr(http_client, "sleep", interrupt)
    monkeypatch.setattr(sys, "argv", [
        "http_client", "--target", "http://localhost/", "--rate", "1",
        "--duration", "30", "--output", str(tmp_path),
    ])
    assert http_client.main() == 130
    report = json.loads(capsys.readouterr().out)
    assert report["result"]["interrupted"]
    metadata = json.loads((Path(report["export_directory"]) / "run.json").read_text(encoding="utf-8"))
    assert metadata["state"] == "interrupted"
    assert metadata["summary"]["attempted"] == 1


def test_export_failure_before_run_does_not_send_traffic(tmp_path, monkeypatch, capsys):
    blocked_path = tmp_path / "file-not-directory"
    blocked_path.write_text("Not a directory", encoding="utf-8")

    def unexpected_send(*args, **kwargs):
        pytest.fail("Traffic was sent before the output directory was validated")

    monkeypatch.setattr(http_client, "send_request", unexpected_send)
    monkeypatch.setattr(sys, "argv", [
        "http_client", "--target", "http://localhost/", "--rate", "1",
        "--duration", "1", "--output", str(blocked_path),
    ])
    with pytest.raises(SystemExit) as exc:
        http_client.main()
    assert exc.value.code == 2
    assert "Export failed" in capsys.readouterr().err
