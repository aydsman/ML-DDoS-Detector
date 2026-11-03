# Legitimate HTTP client: local checkpoints

Owner: Mujtaba. The client sends one GET request or a paced run and prints draft
JSON results. Paced runs have unique run IDs and optional incremental JSON/CSV exports.
PR #7 is merged after Ayden took over the outstanding review on November 2.
Vince reported protected-service runs at the older ba6a521 revision; those artifacts
retain that provenance. The initial status-only 2xx convention and result mapping
are recorded in [measurement-formats.md](measurement-formats.md). Updated-version
lab measurements and full pipeline acceptance remain later evidence, not results
claimed by the merge.

## Try it locally on Windows

From the repository root, start a server in one PowerShell terminal:

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1
```

In a second terminal in the same repository, send one request:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5
```

The output records `started_at` (UTC), `epoch_seconds` (Unix seconds), `elapsed_ms`
(including response body receipt), `outcome`, `status_code`, and `error_type`.
`request_index` is 0 for single-request mode. A 404 or 503 remains an
`http_response`; a timeout or transport failure has no status code. Exit code 0
means a 2xx response, 1 means another result, and 2 means invalid command settings.
The initial named status-only predicate is `http_get_status_2xx_v1`, accepted in
Ayden's PR #7 review following Mujtaba's component-side agreement.

The timeout is HTTPX's per-operation timeout, not a total request deadline.
Redirects are not followed and environment proxies are disabled. Normal TLS
certificate verification remains enabled. Use a local or agreed lab target.

Targets are restricted to `localhost`, `127.0.0.1`, `::1`, and the protected lab
server `10.10.10.10`; other hosts are rejected before sending. The legitimate
client caps `--rate` at 100 requests/second, including concurrent mode. Start at
1-2 requests/second; the cap is an initial project guardrail, not a tuned load
recommendation. Any change to lab addresses or this limit requires a code review.

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
and achieved requests per second. The W1 field mapping is recorded in the measurement specification.

By default, one request is active at a time. Dispatches use a fixed monotonic
grid, with interval `1 / rate`, anchored at run start. Small late wakeups do not
shift future slots. Whole missed slots are skipped and counted as
`skipped_due_to_lag`; only the latest due slot can be dispatched after a delay.
Slow responses lower achieved rate. The client does not replay missed traffic.
At normal completion, lag includes every remaining pre-deadline slot missed by
the final slow response or an overslept scheduler wait. For example, at 2 requests
per second for 2 seconds, a first response taking 3 seconds produces one attempt
and three lag skips. Two responses taking 1.2 seconds each produce indices 1 and
3, two attempts, and two lag skips.
Duration is the request-start window: no request begins at or after its end, but
an in-flight request can finish afterward. Achieved rate uses the total measured
elapsed time, including any final request completion. HTTPX timeouts remain
per-operation rather than total deadlines. Results remain in memory for the
console report and are also flushed to CSV as they complete when `--output` is set.

The command exits with code 0 only if at least one request was attempted and all
returned 2xx responses. This CLI exit convention does not evaluate the detector.

## Allow overlapping requests

Use `--concurrency` to allow 1-32 active requests (default 1). For example:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5 --rate 2 --duration 5 --concurrency 4 --output results
```

This still requests two dispatches per second; four is the maximum number active,
not four times the rate. A slow response can overlap later requests. Dispatches
are paced on a monotonic clock, so worker startup and scheduling can introduce
jitter in actual start times. Optional random traffic jitter is not implemented.
Requests keep individual UTC and epoch start timestamps and
latencies measured inside the worker, excluding executor scheduling delay.

If all slots are occupied, the scheduled attempt is skipped and counted in
`skipped_due_to_capacity`. It is not a failed HTTP request and has no CSV row.
There is no unbounded pending queue and no catch-up traffic. Workers also check
the duration deadline before starting; delayed dispatches dropped at that point
are counted in `skipped_at_deadline`. Dispatches stopped intentionally on
interruption are cancellations instead of deadline or lag skips.
In-flight requests are allowed to complete
after the start window. Results remain in dispatch order even if replies arrive
in a different order in the console report. Live CSV rows are written in completion
order; finalization reconciles the CSV into dispatch order before publishing the
summary. Use `request_index` as the stable request identity. Concurrency is recorded
in settings and skipped counts in the summary.

Sequential mode waits for the active response before considering another request,
so its capacity-skip count stays zero; compare requested and achieved rate there.
The client uses a shared thread-safe HTTPX Client, with at most 32 workers. A fast
local server may show little difference; concurrency helps when responses are slow.

## Save run settings and results

Add `--output results` to a paced run:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5 --rate 2 --duration 5 --output results
```

The output folder and initial metadata are created before requests start.
After the run finishes or is interrupted, the console prints `export_directory`,
the absolute path. Each run gets a generated UUID, independent of the detector:

```text
results/
  <run-id>/
    run.json
    requests.csv
```

- `run.json`: schema version `draft-2`, run ID, traffic type `legitimate_http`,
  target, timeout, requested rate/duration, concurrency, UTC start, elapsed duration,
  achieved request rate, attempts, 2xx responses, outcome counts, skipped counts,
  total `scheduled_slots`, intentionally `cancelled_slots`,
  and interruption status. `state` starts as `running`, with a null summary, then
  becomes `complete` or `interrupted`. A complete run may include HTTP failures.
- `requests.csv`: one row per attempted request with `run_id`, 1-based
  scheduled-slot `request_index`, `started_at` (UTC), `epoch_seconds`, `elapsed_ms`,
  `outcome`, `status_code`, and `error_type`. Indices may have gaps for skipped
  slots. A missing status or error is an empty CSV field; it is not zero.
  HTTP 4xx/5xx responses keep their status and `http_response` outcome.

Both timestamp formats describe the same instant. `epoch_seconds` is a UTC Unix
timestamp; `floor(epoch_seconds)` maps it to an epoch-aligned one-second interval
`[second, second + 1)`. The merged window helper uses this epoch grid; actual offline/live adapters
must still demonstrate matching alignment and coverage.
Synchronize client/server clocks before comparing measurements across machines.
Schema `draft-2` changes the CSV and adds live-export state; older `draft-1` exports
remain readable separately and are never rewritten.

New runs reconcile the complete planned workload:

```text
scheduled_slots = attempted + skipped_due_to_lag + skipped_due_to_capacity
                  + skipped_at_deadline + cancelled_slots
```

`scheduled_slots` counts grid points strictly before the deadline. Normal runs
have zero cancellations. On interruption, unvisited slots and worker dispatches
stopped before sending count as `cancelled_slots`, not ordinary lag. A request
that actually starts and is then interrupted remains an attempt. The two new
summary fields are additive within `draft-2`; older exports may lack them and
may undercount tail skips. Missing fields are not measured zeros. Existing lab
files are not modified by this fix; Ali should retain each run's code revision.

Share both files with Ali. These are independent client observations, not detector
predictions, packet captures, or proof of detection accuracy. The W1 identifiers, initial success predicate and export mapping are
recorded in the measurement specification; preserve its limits on interpretation. HTTP request rates
are not packet rates. Rate, concurrency, operation timeouts, and final in-flight
completion all affect the offered workload; retain these settings with the results.

With `--output`, CSV headers and each completed row are flushed immediately,
including rows produced by workers. Ctrl+C stops scheduling and preserves
completed results; concurrent requests already in flight finish before the final
summary is written. This drain can take longer than the configured duration
because timeouts are per operation. In sequential mode, Ctrl+C during a request
records that attempt with an `interrupted` outcome. An orderly interruption marks
the run `interrupted` and returns exit code 130. Without `--output`, results are
only retained in the printed console report.

Before publishing any finished summary, finalization rebuilds the CSV from the
completed records using a temporary file and atomic replacement. This recovers a
result collected immediately before Ctrl+C even if its incremental write was
missed, buffered, or partial. Each identity appears once; retrying finalization
does not append duplicates. Final CSV counts and identities match the completed
records and JSON summary. Consumers watching a live CSV should reopen it after
the state changes, since the finalized file replaces the incremental one.

A process crash can leave `state: running`, a null summary, and the rows flushed
so far. Treat that as incomplete; a request in flight may have no completed row.
Metadata updates use a temporary file and atomic replacement, so readers do not
see half-written JSON. A reconciliation failure leaves the export unfinished
instead of publishing a summary for missing rows. Existing run folders are never
overwritten. I/O failure
exits with code 2; previously flushed rows may remain, but an export must not be
treated as complete unless its state says so. Runs with request failures still
export and exit with code 1. Unexpected ordinary request exceptions are recorded
as `unexpected_error` with their exception class and no status code.

Skipped slots are counters in JSON, not HTTP attempts or CSV rows. The measurement specification accepts this representation as workload
accounting; it is not packet-level ground truth. Counts cannot reconstruct
the exact timestamp of every skipped slot, and client logs do not prove which
packets arrived at the server.
The `results/` folder is already gitignored. Without `--output`, the client prints
results without writing files. Single-request mode does not accept `--output`.

## Linux and protected-service integration

Run these from the repository root with the project's Python 3.12 environment
and dependencies installed. Local Linux test server (first terminal):

```bash
./.venv/bin/python -m http.server 8000 --bind 127.0.0.1
```

Client (second terminal):

```bash
./.venv/bin/python -m ddos_detector.http_client --target http://127.0.0.1:8000/ --timeout 5 --rate 2 --duration 5 --concurrency 4 --output results
```

In Vince's isolated lab, run on `ddos-client` (`10.10.10.20`) against nginx on
the protected server (`10.10.10.10`), after confirming connectivity with Vince:

```bash
./.venv/bin/python -m ddos_detector.http_client --target http://10.10.10.10/ --timeout 5 --rate 2 --duration 10 --concurrency 4 --output results
```

Repeat the same command to get another independent run ID and export folder.
These are integration instructions, not evidence that the lab test has passed.

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
Concurrency tests hold slow responses to prove overlap, the worker limit, skipped
capacity, completion ordering, and the absence of queued requests after deadline.
Review-fix tests check target/rate restrictions, matching ISO/epoch times, fixed-grid
pacing, incremental readability, crash remnants, and interrupted-run exports.
`tests/test_http_client_accounting.py` adds issue #13 regressions for response
overrun, scheduler oversleep, cancellation accounting, real SIGINT between result
collection and CSV persistence, repeated finalization, and reconciliation failure.
