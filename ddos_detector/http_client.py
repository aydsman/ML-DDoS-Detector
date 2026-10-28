"""Measure legitimate HTTP GET requests, individually or in a paced run.

Run with: python -m ddos_detector.http_client --target http://127.0.0.1:8000/
"""

import argparse
import csv
import json
import math
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter, sleep
from uuid import UUID, uuid4

import httpx


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
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("Timeout must be a finite number greater than zero.")


@dataclass(frozen=True)
class RequestResult:
    started_at: str
    elapsed_ms: float
    outcome: str
    status_code: int | None
    error_type: str | None


@dataclass(frozen=True)
class RunSettings:
    request_rate: float
    duration_seconds: float

    def __post_init__(self):
        for name, value in (
            ("Request rate", self.request_rate),
            ("Duration", self.duration_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite number greater than zero.")
        if not math.isfinite(1 / self.request_rate):
            raise ValueError("Request rate is too small to schedule.")


@dataclass(frozen=True)
class RunResult:
    started_at: str
    elapsed_seconds: float
    achieved_requests_per_second: float
    attempted: int
    successful_2xx: int
    requests: list[RequestResult]
    run_id: str = field(default_factory=lambda: str(uuid4()))


def export_run(
    output_dir: Path, settings: ClientSettings, run: RunSettings, result: RunResult
) -> Path:
    """Write draft exports in a unique directory; never replace an earlier run.

    Write run.json after requests.csv. An I/O failure can leave partial files;
    errors reach the caller, so only a successful return confirms completion.
    """
    # Run IDs are generated UUIDs. Validate before using one as a path component.
    if str(UUID(result.run_id)) != result.run_id:
        raise ValueError("Run ID must be a canonical UUID.")
    run_dir = Path(output_dir) / result.run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    columns = [
        "run_id", "request_index", "started_at", "elapsed_ms", "outcome",
        "status_code", "error_type",
    ]
    with (run_dir / "requests.csv").open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for index, request in enumerate(result.requests, start=1):
            writer.writerow({
                "run_id": result.run_id, "request_index": index, **asdict(request),
            })
    summary = {
        "started_at": result.started_at,
        "elapsed_seconds": result.elapsed_seconds,
        "achieved_requests_per_second": result.achieved_requests_per_second,
        "attempted": result.attempted,
        "successful_2xx": result.successful_2xx,
        "outcome_counts": dict(Counter(item.outcome for item in result.requests)),
    }
    with (run_dir / "run.json").open("x", encoding="utf-8") as handle:
        json.dump({
            "schema_version": "draft-1",
            "run_id": result.run_id,
            "traffic_type": "legitimate_http",
            "settings": {**asdict(settings), **asdict(run)},
            "summary": summary,
            "requests_file": "requests.csv",
        }, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return run_dir


def run_requests(client: httpx.Client, settings: ClientSettings, run: RunSettings) -> RunResult:
    """Pace one request at a time, with no catch-up bursts or queued requests.

    Duration limits when requests may start. A final in-flight request may
    finish later. Slow responses reduce achieved rate below requested rate.
    Results are held in memory for these initial small local experiments.
    """
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    start = perf_counter()
    deadline = start + run.duration_seconds
    next_start = start
    interval = 1 / run.request_rate
    results = []
    while True:
        now = perf_counter()
        if now >= deadline:
            break
        wait = min(next_start, deadline) - now
        if wait > 0:
            sleep(wait)
        now = perf_counter()
        if now >= deadline:
            break
        next_start = now + interval
        results.append(send_request(client, settings))
    elapsed = perf_counter() - start
    return RunResult(
        started_at=started_at,
        elapsed_seconds=elapsed,
        achieved_requests_per_second=len(results) / elapsed,
        attempted=len(results),
        successful_2xx=sum(
            result.status_code is not None and 200 <= result.status_code < 300
            for result in results
        ),
        requests=results,
    )


def send_request(client: httpx.Client, settings: ClientSettings) -> RequestResult:
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
    return RequestResult(
        started_at=started_at,
        elapsed_ms=(perf_counter() - start) * 1000,
        outcome=outcome,
        status_code=status_code,
        error_type=error_type,
    )


def main():
    parser = argparse.ArgumentParser(description="Send one HTTP GET or a paced run of requests.")
    parser.add_argument("--target", required=True, help="Absolute HTTP or HTTPS URL")
    parser.add_argument("--timeout", type=float, default=5.0, help="Operation timeout in seconds")
    parser.add_argument("--rate", type=float, help="Requested starts per second; requires --duration")
    parser.add_argument("--duration", type=float, help="Request-start window in seconds; requires --rate")
    parser.add_argument("--output", type=Path, help="Save paced-run JSON and CSV files under this folder")
    args = parser.parse_args()
    if (args.rate is None) != (args.duration is None):
        parser.error("Supply --rate and --duration together, or omit both for one request.")
    if args.output is not None and args.rate is None:
        parser.error("--output requires a paced run with --rate and --duration.")
    try:
        settings = ClientSettings(args.target, args.timeout)
        run = RunSettings(args.rate, args.duration) if args.rate is not None else None
    except ValueError as exc:
        parser.error(str(exc))
    # Avoid machine-specific proxy settings affecting isolated lab requests.
    with httpx.Client(trust_env=False) as client:
        if run is not None:
            result = run_requests(client, settings, run)
            report = {
                "settings": {**asdict(settings), **asdict(run)},
                "result": asdict(result),
            }
            if args.output is not None:
                try:
                    report["export_directory"] = str(export_run(args.output, settings, run, result).resolve())
                except OSError as exc:
                    # Keep measured results visible even when files cannot be saved.
                    print(json.dumps(report, indent=2))
                    parser.exit(2, f"Export failed: {exc}\n")
            print(json.dumps(report, indent=2))
            return 0 if result.attempted > 0 and result.successful_2xx == result.attempted else 1
        result = send_request(client, settings)
        print(json.dumps(asdict(result), indent=2))
        return 0 if result.status_code is not None and 200 <= result.status_code < 300 else 1


if __name__ == "__main__":
    raise SystemExit(main())
