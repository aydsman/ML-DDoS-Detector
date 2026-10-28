"""Measure legitimate HTTP GET requests, individually or in a paced run.

Run with: python -m ddos_detector.http_client --target http://127.0.0.1:8000/
"""

import argparse
import csv
import json
import math
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock
from time import perf_counter, sleep
from uuid import UUID, uuid4

import httpx

MAX_REQUEST_RATE = 100.0
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "10.10.10.10"}


@dataclass(frozen=True)
class ClientSettings:
    target: str
    timeout_seconds: float = 5.0

    def __post_init__(self):
        try:
            url = httpx.URL(self.target)
        except httpx.InvalidURL as exc:
            raise ValueError("Target must be an absolute HTTP or HTTPS URL.") from exc
        if url.scheme not in ("http", "https") or not url.host:
            raise ValueError("Target must be an absolute HTTP or HTTPS URL.")
        if url.username or url.password:
            raise ValueError("Do not include credentials in the target URL.")
        if url.host not in ALLOWED_HOSTS:
            raise ValueError("Target must be localhost, 127.0.0.1, ::1, or the lab server 10.10.10.10.")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("Timeout must be a finite number greater than zero.")


@dataclass(frozen=True)
class RequestResult:
    started_at: str
    elapsed_ms: float
    outcome: str
    status_code: int | None
    error_type: str | None
    request_index: int = 0
    epoch_seconds: float = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "epoch_seconds", datetime.fromisoformat(self.started_at).timestamp())


@dataclass(frozen=True)
class RunSettings:
    request_rate: float
    duration_seconds: float
    concurrency: int = 1

    def __post_init__(self):
        for name, value in (
            ("Request rate", self.request_rate),
            ("Duration", self.duration_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite number greater than zero.")
        if not math.isfinite(1 / self.request_rate):
            raise ValueError("Request rate is too small to schedule.")
        if self.request_rate > MAX_REQUEST_RATE:
            raise ValueError(f"Request rate must not exceed {MAX_REQUEST_RATE:g} requests/second.")
        if type(self.concurrency) is not int or not 1 <= self.concurrency <= 32:
            raise ValueError("Concurrency must be an integer from 1 to 32.")


@dataclass(frozen=True)
class RunResult:
    started_at: str
    elapsed_seconds: float
    achieved_requests_per_second: float
    attempted: int
    successful_2xx: int
    requests: list[RequestResult]
    run_id: str = field(default_factory=lambda: str(uuid4()))
    skipped_due_to_capacity: int = 0
    skipped_at_deadline: int = 0
    skipped_due_to_lag: int = 0
    interrupted: bool = False


def _summary(result):
    return {
        "started_at": result.started_at,
        "elapsed_seconds": result.elapsed_seconds,
        "achieved_requests_per_second": result.achieved_requests_per_second,
        "attempted": result.attempted,
        "successful_2xx": result.successful_2xx,
        "skipped_due_to_capacity": result.skipped_due_to_capacity,
        "skipped_at_deadline": result.skipped_at_deadline,
        "skipped_due_to_lag": result.skipped_due_to_lag,
        "interrupted": result.interrupted,
        "outcome_counts": dict(Counter(item.outcome for item in result.requests)),
    }


class RunExport:
    """Flush completed request rows immediately, including from worker threads."""

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.run_dir = None
        self.handle = None
        self.lock = Lock()

    def begin(self, settings, run, run_id, started_at):
        if str(UUID(run_id)) != run_id:
            raise ValueError("Run ID must be a canonical UUID.")
        self.run_dir = self.output_dir / run_id
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.metadata = {
            "schema_version": "draft-2",
            "run_id": run_id,
            "traffic_type": "legitimate_http",
            "settings": {**asdict(settings), **asdict(run)},
            "started_at": started_at,
            "state": "running",
            "summary": None,
            "requests_file": "requests.csv",
        }
        self._write_metadata()
        self.handle = (self.run_dir / "requests.csv").open("x", encoding="utf-8", newline="")
        self.writer = csv.DictWriter(self.handle, fieldnames=[
            "run_id", "request_index", "started_at", "epoch_seconds",
            "elapsed_ms", "outcome", "status_code", "error_type",
        ])
        self.writer.writeheader()
        self.handle.flush()

    def _write_metadata(self):
        # Readers see the old complete JSON or the new complete JSON.
        temporary = self.run_dir / "run.json.tmp"
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(self.metadata, handle, indent=2, allow_nan=False)
            handle.write("\n")
        temporary.replace(self.run_dir / "run.json")

    def record(self, request, fallback_index=0):
        with self.lock:
            row = asdict(request)
            row["request_index"] = request.request_index or fallback_index
            self.writer.writerow({"run_id": self.metadata["run_id"], **row})
            self.handle.flush()

    def finish(self, result):
        self.metadata["state"] = "interrupted" if result.interrupted else "complete"
        self.metadata["summary"] = _summary(result)
        self._write_metadata()

    def close(self):
        if self.handle is not None:
            self.handle.close()


def export_run(output_dir, settings, run, result):
    """Export an already collected result; the CLI uses incremental RunExport."""
    export = RunExport(output_dir)
    try:
        export.begin(settings, run, result.run_id, result.started_at)
        for index, request in enumerate(result.requests, start=1):
            export.record(request, fallback_index=index)
        export.finish(result)
        return export.run_dir
    finally:
        export.close()


def _scheduled_slots(start, deadline, interval, counters):
    """Use a fixed grid and skip elapsed slots rather than sending a backlog."""
    slot = 0
    while True:
        due = start + slot * interval
        if due >= deadline:
            remaining = deadline - perf_counter()
            if remaining > 0:
                sleep(remaining)
            return
        now = perf_counter()
        if now >= deadline:
            return
        if due > now:
            sleep(due - now)
            now = perf_counter()
        if now >= deadline:
            return
        # Slightly late wakeups use the current slot. Whole missed intervals
        # are dropped, so lateness never accumulates into a catch-up queue.
        latest = max(slot, math.floor((now - start) / interval))
        counters["lag"] += latest - slot
        slot = latest
        yield slot + 1
        slot += 1


def _concurrent_requests(client, settings, run, start, deadline, counters, export):
    """Bound submitted work as well as worker threads; discard busy slots.

    HTTPX's synchronous Client is shared across workers. A worker rechecks the
    deadline before sending, so delayed dispatch does not create late requests.
    Keep results in dispatch order, independent of response completion order.
    """
    interval = 1 / run.request_rate
    pending = {}
    completed = {}
    skipped_capacity = 0
    skipped_deadline = 0
    interrupted = False
    stop = Event()

    def dispatch(index):
        if stop.is_set() or perf_counter() >= deadline:
            return None
        result = send_request(client, settings, request_index=index)
        if export is not None:
            export.record(result)
        return result

    def collect(future):
        nonlocal skipped_deadline
        index = pending[future]
        result = future.result()
        pending.pop(future)
        if result is None:
            skipped_deadline += 1
        else:
            completed[index] = result

    with ThreadPoolExecutor(max_workers=run.concurrency) as executor:
        try:
            for index in _scheduled_slots(start, deadline, interval, counters):
                for future in list(pending):
                    if future.done():
                        collect(future)
                if len(pending) >= run.concurrency:
                    skipped_capacity += 1
                    continue
                pending[executor.submit(dispatch, index)] = index
        except KeyboardInterrupt:
            interrupted = True
            stop.set()
        # No more submissions. Finish in-flight requests before exporting.
        for future in list(pending):
            while future in pending:
                try:
                    collect(future)
                except KeyboardInterrupt:
                    interrupted = True
                    stop.set()
    return [completed[index] for index in sorted(completed)], skipped_capacity, skipped_deadline, interrupted


def run_requests(client: httpx.Client, settings: ClientSettings, run: RunSettings, export=None) -> RunResult:
    """Pace requests with a configurable limit and no catch-up bursts.

    Duration limits when requests may start. A final in-flight request may
    finish later. Slow responses and a full worker limit can reduce achieved rate.
    Completed results are also flushed incrementally when an export is supplied.
    """
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    run_id = str(uuid4())
    if export is not None:
        export.begin(settings, run, run_id, started_at)
    start = perf_counter()
    deadline = start + run.duration_seconds
    interval = 1 / run.request_rate
    results = []
    skipped_capacity = 0
    skipped_deadline = 0
    counters = {"lag": 0}
    interrupted = False
    if run.concurrency > 1:
        results, skipped_capacity, skipped_deadline, interrupted = _concurrent_requests(
            client, settings, run, start, deadline, counters, export
        )
    else:
        try:
            for index in _scheduled_slots(start, deadline, interval, counters):
                result = send_request(client, settings, request_index=index)
                results.append(result)
                if export is not None:
                    export.record(result)
                if result.outcome == "interrupted":
                    interrupted = True
                    break
        except KeyboardInterrupt:
            interrupted = True
    elapsed = perf_counter() - start
    result = RunResult(
        started_at=started_at,
        elapsed_seconds=elapsed,
        achieved_requests_per_second=len(results) / elapsed if elapsed else 0.0,
        attempted=len(results),
        successful_2xx=sum(
            result.status_code is not None and 200 <= result.status_code < 300
            for result in results
        ),
        requests=results,
        skipped_due_to_capacity=skipped_capacity,
        skipped_at_deadline=skipped_deadline,
        skipped_due_to_lag=counters["lag"],
        interrupted=interrupted,
        run_id=run_id,
    )
    if export is not None:
        export.finish(result)
    return result


def send_request(client: httpx.Client, settings: ClientSettings, request_index=0) -> RequestResult:
    """Measure through receipt of the response body, or until a request fails.

    HTTP status errors remain responses, distinct from transport errors.
    The timeout applies to HTTPX's connect/read/write/pool operations, not a
    strict wall-clock deadline for the whole request.
    """
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    start = perf_counter()
    status_code = None
    error_type = None
    try:
        response = client.get(
            settings.target, timeout=settings.timeout_seconds, follow_redirects=False
        )
        status_code = response.status_code
        outcome = "http_response"
    except httpx.TimeoutException as exc:
        outcome = "timeout"
        error_type = type(exc).__name__
    except httpx.RequestError as exc:
        outcome = "request_error"
        error_type = type(exc).__name__
    except KeyboardInterrupt:
        outcome = "interrupted"
        error_type = "KeyboardInterrupt"
    except Exception as exc:
        outcome = "unexpected_error"
        error_type = type(exc).__name__
    return RequestResult(
        started_at=started_at,
        elapsed_ms=(perf_counter() - start) * 1000,
        outcome=outcome,
        status_code=status_code,
        error_type=error_type,
        request_index=request_index,
    )


def main():
    parser = argparse.ArgumentParser(description="Send one HTTP GET or a paced run of requests.")
    parser.add_argument("--target", required=True, help="Absolute HTTP or HTTPS URL")
    parser.add_argument("--timeout", type=float, default=5.0, help="Operation timeout in seconds")
    parser.add_argument("--rate", type=float, help="Requested starts per second, maximum 100; requires --duration")
    parser.add_argument("--duration", type=float, help="Request-start window in seconds; requires --rate")
    parser.add_argument("--output", type=Path, help="Save paced-run JSON and CSV files under this folder")
    parser.add_argument("--concurrency", type=int, default=1, help="Maximum active requests, 1-32 (default: 1)")
    args = parser.parse_args()
    if (args.rate is None) != (args.duration is None):
        parser.error("Supply --rate and --duration together, or omit both for one request.")
    if args.output is not None and args.rate is None:
        parser.error("--output requires a paced run with --rate and --duration.")
    if args.concurrency != 1 and args.rate is None:
        parser.error("--concurrency requires a paced run with --rate and --duration.")
    try:
        settings = ClientSettings(args.target, args.timeout)
        run = RunSettings(args.rate, args.duration, args.concurrency) if args.rate is not None else None
    except ValueError as exc:
        parser.error(str(exc))
    # Avoid machine-specific proxy settings affecting isolated lab requests.
    with httpx.Client(trust_env=False) as client:
        if run is not None:
            export = RunExport(args.output) if args.output is not None else None
            try:
                result = run_requests(client, settings, run, export=export)
            except OSError as exc:
                parser.exit(2, f"Export failed; earlier flushed rows may remain in {args.output}: {exc}\n")
            finally:
                if export is not None:
                    export.close()
            report = {
                "settings": {**asdict(settings), **asdict(run)},
                "result": asdict(result),
            }
            if export is not None:
                report["export_directory"] = str(export.run_dir.resolve())
            print(json.dumps(report, indent=2))
            if result.interrupted:
                return 130
            return 0 if result.attempted > 0 and result.successful_2xx == result.attempted else 1
        result = send_request(client, settings)
        print(json.dumps(asdict(result), indent=2))
        return 0 if result.status_code is not None and 200 <= result.status_code < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
