"""Issue #13: scheduled workload and saved requests must reconcile."""

import csv
import inspect
import json
import signal
import sys
from concurrent.futures import Future
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest

import ddos_detector.http_client as http_client
from ddos_detector.http_client import ClientSettings, RunExport, RunSettings, run_requests


@pytest.fixture
def clock(monkeypatch):
    class Clock:
        now = 0.0

        def advance(self, seconds):
            self.now += seconds

    clock = Clock()
    monkeypatch.setattr(http_client, "perf_counter", lambda: clock.now)
    monkeypatch.setattr(http_client, "sleep", clock.advance)
    return clock


def assert_workload_reconciles(result):
    assert result.scheduled_slots == (
        result.attempted + result.skipped_due_to_lag + result.skipped_due_to_capacity
        + result.skipped_at_deadline + result.cancelled_slots
    )


def assert_exports_reconcile(export, result):
    metadata = json.loads((export.run_dir / "run.json").read_text(encoding="utf-8"))
    with (export.run_dir / "requests.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert metadata["state"] == ("interrupted" if result.interrupted else "complete")
    assert len(rows) == len(result.requests) == metadata["summary"]["attempted"]
    assert len({row["request_index"] for row in rows}) == len(rows)
    assert [int(row["request_index"]) for row in rows] == [
        request.request_index for request in result.requests
    ]
    for row, request in zip(rows, result.requests):
        assert row["run_id"] == result.run_id
        for name, value in asdict(request).items():
            assert row[name] == ("" if value is None else str(value))
    assert sum(200 <= int(row["status_code"]) < 300 for row in rows if row["status_code"]) == (
        metadata["summary"]["successful_2xx"]
    )
    assert_workload_reconciles(result)


@pytest.mark.parametrize("latency,indices,missed", [(3.0, [1], 3), (1.2, [1, 3], 2)])
@pytest.mark.parametrize("concurrency", [1, 2])
def test_final_response_overrun_counts_all_remaining_slots(clock, monkeypatch, latency, indices, missed, concurrency):
    # An immediate executor makes scheduler-time overruns deterministic for both
    # paths; real overlapping workers are covered by test_http_client.py.
    class ImmediateExecutor:
        def __init__(self, max_workers):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, action, *args):
            future = Future()
            future.set_result(action(*args))
            return future

    monkeypatch.setattr(http_client, "ThreadPoolExecutor", ImmediateExecutor)

    def respond(request):
        clock.advance(latency)
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2, concurrency))
    assert [request.request_index for request in result.requests] == indices
    assert result.skipped_due_to_lag == missed
    assert not result.interrupted
    assert result.cancelled_slots == 0
    assert_workload_reconciles(result)


def test_scheduler_oversleep_counts_tail_slots(clock, monkeypatch):
    monkeypatch.setattr(http_client, "sleep", lambda seconds: clock.advance(seconds + 3))
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2))
    assert result.attempted == 1
    assert result.skipped_due_to_lag == 3
    assert not result.interrupted
    assert_workload_reconciles(result)


def test_interrupted_tail_is_cancelled_not_lag(clock, monkeypatch):
    def interrupt(seconds):
        clock.advance(0.1)
        raise KeyboardInterrupt

    monkeypatch.setattr(http_client, "sleep", interrupt)
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2))
    assert result.interrupted
    assert result.attempted == 1
    assert result.cancelled_slots == 3
    assert result.skipped_due_to_lag == 0
    assert_workload_reconciles(result)


@pytest.mark.parametrize("boundary", ["before_record", "after_write"])
def test_real_sigint_at_csv_boundary_is_reconciled(tmp_path, clock, boundary):
    function = run_requests if boundary == "before_record" else RunExport.record
    source, start_line = inspect.getsourcelines(function)
    statement = "export.record(result)" if boundary == "before_record" else "self.handle.flush()"
    target_line = next(start_line + index for index, line in enumerate(source) if line.strip() == statement)
    fired = False

    def trace(frame, event, arg):
        nonlocal fired
        if not fired and frame.f_code is function.__code__ and event == "line" and frame.f_lineno == target_line:
            fired = True
            signal.raise_signal(signal.SIGINT)
        return trace

    export = RunExport(tmp_path)
    previous_trace = sys.gettrace()
    previous_handler = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            try:
                sys.settrace(trace)
                result = run_requests(
                    client, ClientSettings("http://localhost/"), RunSettings(2, 2), export=export
                )
            finally:
                sys.settrace(previous_trace)
                signal.signal(signal.SIGINT, previous_handler)
        assert fired
        assert result.interrupted
        assert result.attempted == result.successful_2xx == 1
        assert_exports_reconcile(export, result)
        # Recovery is safe even if finalization is retried more than once.
        export.finish(result)
        export.finish(result)
        assert_exports_reconcile(export, result)
    finally:
        export.close()


@pytest.mark.parametrize("concurrency", [1, 2])
def test_normal_exports_reconcile_after_repeated_finish(tmp_path, concurrency):
    export = RunExport(tmp_path)
    try:
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))) as client:
            result = run_requests(
                client, ClientSettings("http://localhost/"), RunSettings(10, 0.2, concurrency), export=export
            )
        assert result.attempted > 0
        assert not result.interrupted
        assert_exports_reconcile(export, result)
        export.finish(result)
        assert_exports_reconcile(export, result)
    finally:
        export.close()


@pytest.mark.parametrize("start,deadline,interval,expected", [
    (0, 2, 0.5, 4),
    (0, 0.30000000000000004, 0.1, 3),
    (100000, 100000.3, 0.1, 3),
    (0, 0.25, 0.1, 3),
    (5, 5, 0.1, 0),
])
def test_scheduled_count_matches_half_open_grid(start, deadline, interval, expected):
    assert http_client._scheduled_slot_count(start, deadline, interval) == expected


def test_failed_reconciliation_does_not_publish_a_finished_summary(tmp_path, monkeypatch):
    request = http_client.RequestResult("2026-10-28T12:00:00Z", 1, "http_response", 200, None, 1)
    result = http_client.RunResult(
        request.started_at, 1, 1, 1, 1, [request], interrupted=True,
        scheduled_slots=2, cancelled_slots=1,
    )
    export = RunExport(tmp_path)
    original_replace = Path.replace

    def fail_csv_replace(path, target):
        if path.name == "requests.csv.tmp":
            raise OSError("Controlled replacement failure")
        return original_replace(path, target)

    try:
        export.begin(ClientSettings("http://localhost/"), RunSettings(2, 1), result.run_id, result.started_at)
        monkeypatch.setattr(Path, "replace", fail_csv_replace)
        with pytest.raises(OSError, match="Controlled"):
            export.finish(result)
        metadata = json.loads((export.run_dir / "run.json").read_text(encoding="utf-8"))
        assert metadata["state"] == "running"
        assert metadata["summary"] is None
        # Retrying the same finalization repairs the export without a new run ID.
        monkeypatch.setattr(Path, "replace", original_replace)
        export.finish(result)
        assert_exports_reconcile(export, result)
    finally:
        export.close()


def test_interruption_cancels_delayed_workers_without_deadline_skips(clock, monkeypatch):
    class DelayedFuture:
        def __init__(self, action, args):
            self.action, self.args = action, args

        def done(self):
            return False

        def result(self):
            return self.action(*self.args)

    class DelayedExecutor:
        def __init__(self, max_workers):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def submit(self, action, *args):
            return DelayedFuture(action, args)

    def interrupt(seconds):
        clock.advance(0.1)
        raise KeyboardInterrupt

    def unexpected_request(request):
        pytest.fail("A cancelled worker sent traffic")

    monkeypatch.setattr(http_client, "sleep", interrupt)
    monkeypatch.setattr(http_client, "ThreadPoolExecutor", DelayedExecutor)
    with httpx.Client(transport=httpx.MockTransport(unexpected_request)) as client:
        result = run_requests(client, ClientSettings("http://localhost/"), RunSettings(2, 2, 2))
    assert result.interrupted
    assert result.attempted == result.skipped_at_deadline == result.skipped_due_to_lag == 0
    assert result.cancelled_slots == 4
    assert_workload_reconciles(result)
