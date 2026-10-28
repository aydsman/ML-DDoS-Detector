# Legitimate HTTP client: local checkpoints

Owner: Mujtaba. The client sends one GET request or a paced run and prints draft
JSON results. Paced runs have unique run IDs and optional JSON/CSV exports.
Protected-service integration is still pending, so the W1 task is not complete.
Ali still needs to review result fields and success criteria.

## Try it locally on Windows

From the repository root, start a server in one PowerShell terminal:

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1
```

In a second terminal in the same repository, send one request:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5
```

The output records `started_at` (UTC), `elapsed_ms` (including response body
receipt), `outcome`, `status_code`, and `error_type`. A 404 or 503 remains an
`http_response`; a timeout or transport failure has no status code. Exit code 0
means a 2xx response, 1 means another result, and 2 means invalid command settings.
The 2xx success convention is provisional until agreed with Ali.

The timeout is HTTPX's per-operation timeout, not a total request deadline.
Redirects are not followed and environment proxies are disabled. Normal TLS
certificate verification remains enabled. Use a local or agreed lab target.

Stop the local server with Ctrl+C, then repeat the client command to observe a
connection-error record. A nonexistent path on the running server returns 404.
Do not interpret this smoke test as protected-service integration evidence.

## Repeat requests at a controlled rate

With the local server running, request twice per second for five seconds:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5 --rate 2 --duration 5
```

Supply both `--rate` and `--duration` for a run. Omit both for the original
single-request behavior. Output appears after the run finishes and contains the
settings, individual request results, attempted count, 2xx count, elapsed seconds,
and achieved requests per second. These fields are a draft for Ali to review.

The first request starts immediately. At most one request is active at a time;
start times are spaced at least `1 / rate` seconds apart. Slow responses lower the
achieved rate; the client never queues missed requests or sends catch-up bursts.
Duration is the request-start window: no request begins at or after its end, but
an in-flight request can finish afterward. Achieved rate uses the total measured
elapsed time, including any final request completion. HTTPX timeouts remain
per-operation rather than total deadlines. Small local runs hold results in memory;
bounded concurrent operation and streaming exports can be considered separately.

The command exits with code 0 only if at least one request was attempted and all
returned 2xx responses. This is a provisional convention, not detector evaluation.

## Save run settings and results

Add `--output results` to a paced run:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5 --rate 2 --duration 5 --output results
```

After the run finishes, the console prints `export_directory`, the absolute path
to the new folder. Each run gets a generated UUID, independent of the detector:

```text
results/
  <run-id>/
    run.json
    requests.csv
```

- `run.json`: schema version `draft-1`, run ID, traffic type `legitimate_http`,
  target, timeout, requested rate/duration, UTC start, elapsed duration, achieved
  request rate, attempts, 2xx responses, and outcome counts.
- `requests.csv`: one row per attempted request with `run_id`, 1-based
  `request_index`, `started_at` (UTC), `elapsed_ms`, `outcome`, `status_code`, and
  `error_type`. A missing status or error is an empty CSV field; it is not zero.
  HTTP 4xx/5xx responses keep their status and `http_response` outcome.

Share both files with Ali. These are independent client observations, not detector
predictions, packet captures, or proof of detection accuracy. Ali still needs to
approve identifiers, success criteria, and the export schema. HTTP request rates
are not packet rates. The current generator runs sequentially and records that
behavior here; no concurrent-load capability is claimed.

Exports happen only after normal run completion; interruption does not save a
partial run. Existing run folders are never overwritten. `run.json` is written
last; an I/O failure can leave missing or partially written files. Only a successful
export confirms completion; file presence alone is not sufficient.
Export failure prints an error and exits with code 2, preserving measured results
in console output. Runs with request failures still export and exit with code 1.
The `results/` folder is already gitignored. Without `--output`, the client prints
results without writing files. Single-request mode does not accept `--output`.

## Automated checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Client tests cover invalid settings, response statuses, simulated timeout and
connection failures, and a real request to a temporary loopback HTTP server.
Virtual-clock tests verify pacing, reduced achieved rate with slow responses,
and completion of in-flight requests after the start window closes.
Export tests check JSON/CSV agreement, missing statuses, run IDs, non-overwrite
behavior, and a full CLI run against the temporary local server.
