# Measurement definitions and run records

Status: W1 draft for component-owner review. Owner: Ali. This document defines proposed experiment records and calculations; it contains no experiment results or agreed performance targets. See the [test plan](test-plan.md), [design](design.md), [API contract](api-contract.md), and unresolved decisions in [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5). Use the design together with the later [provisional label decision](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428267359) and [approved baseline settings](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428534359). The test plan separates merged support code from still-unverified lab facts and pending integration.

## Collection rules

- Copy [the blank run record](templates/run-record.template.json) to `results/<run_id>/run-record.json`. Keep generated records/results in gitignored `results/`, raw logs in `logs/`, and captures/datasets in `data/`. Commit only the blank template and documentation.
- Replace `record_type: "template"` with `"experiment"` only for an actual run. Use a unique `run_id`; link matched trials with `comparison_id`. A planned run may still have `status: "not_run"`. Test statuses are `not_run`, `blocked`, `passed`, or `failed`; passing requires the scenario's stated evidence. These are test results, not service health states.
- Use UTC ISO 8601 timestamps ending in `Z`, seconds for durations, bytes for memory, and numeric proportions from 0 to 1. Intervals are `[start, end)`. Retain original timestamps/timezone and conversion evidence in the source artifact.
- `null` means unknown, unavailable, or not applicable; provide a reason. Zero means a measured zero. Empty arrays in the template mean no records collected, not proof that no attacks, failures, or blocks occurred.
- Preserve raw evidence, collection commands/tool versions, Git commit and dirty state, resolved package versions, configuration, model/dataset references, and SHA-256 hashes. Calculate hashes after files are closed. Do not place secrets in the record.
- Independently establish traffic labels from verified dataset metadata or generator identities, protocol, target, and actual start/end logs. Detector scores, alert decisions, firewall actions, and assumed schedules are never ground truth.
- Use one record per aggregate window. The provisional attack-packet fraction is `X = 0.80`, with sensitivity checks on validation data only. First exclude unavailable capture, unknown labels, boundary-crossing and empty windows. Among fully labelled, nonempty, nonboundary windows, label attack when the independently identified attack fraction is at least X; label benign only with zero attack packets and independent benign evidence outside attack intervals. Exclude other mixed windows and attack-interval windows with zero confirmed attack packets. Retain every exclusion reason/count. The provisional threshold does not verify actual files, splits or ground truth.
- Keep the model decision threshold separate: `0.5` is an experimental baseline, tuned only on validation data. Never tune either threshold or the mitigation policy on final-test outcomes.
- Use `window_alignment: "unix_epoch"` and `start = floor(ts / window_seconds) * window_seconds`, with `[start, end)` bounds shared by offline/live paths. Record feature schema version `"1"` and the exact ordered names; do not infer alignment from the first packet.

## Metrics and denominators

### Aggregate-window classification

Join independently labelled windows to complete per-window inference logs by `window_id`. The dashboard's limited detection history is insufficient: inference collection must include negative predictions too. Source-attribution events never add classifier observations. One aggregate window has one prediction; duplicated/conflicting predictions require investigation before scoring.

An evaluable window has a reviewed `attack` or `benign` label, valid capture evidence, and an available aggregate prediction. Prediction is the recorded stage-1 decision using the recorded threshold; do not infer it from a source block request. Use all evaluable held-out windows in the declared reporting interval, separately by scenario and split.

| Metric | Calculation |
| --- | --- |
| TP / FN | Independently attack-labelled windows predicted attack / predicted benign |
| FP / TN | Independently benign-labelled windows predicted attack / predicted benign |
| Accuracy | `(TP + TN) / (TP + TN + FP + FN)` |
| Precision | `TP / (TP + FP)` |
| Recall | `TP / (TP + FN)` |
| F1 | `2*TP / (2*TP + FP + FN)` |
| False-positive rate | `FP / (FP + TN)`; denominator is evaluable benign windows |
| Prediction coverage | Evaluable windows / independently eligible windows with valid capture |

A zero denominator produces `null` with reason `zero_denominator`, never an invented perfect score. Publish TP, TN, FP, FN, eligible count, missing-prediction count, and exclusion counts beside the ratios. Missing predictions are unobserved, not benign predictions or false negatives; report them separately. A classification score with incomplete prediction/capture coverage must be labelled partial and cannot establish full-system acceptance. Unknown/mixed excluded windows do not enter the headline confusion matrix. Keep per-run values; do not pool test data into training or threshold tuning.

### Event detection delay

For each independently confirmed attack interval, match the first positive aggregate prediction whose eligible attack-labelled window overlaps that interval. Retain the window, prediction, generator-interval, and evidence IDs. The proposed matching horizon is the attack end plus a predeclared inference grace period; its value needs review. Do not count an earlier unrelated alert, source-attribution event, or a dashboard refresh as first detection.

`detection_delay_seconds = prediction.inference_at - generator_interval.start_at`, after clock correction. Record clock offset estimates and conservative uncertainty bounds for both hosts. If their combined uncertainty is `u`, report `[delay-u, delay+u]` with the point estimate. A negative estimate or an interval spanning zero means ordering is uncertain; flag it and do not silently clamp it. A missing clock bound makes cross-host delay unavailable.

Record every attack interval as `detected`, `not_detected`, or `unobservable`. `not_detected` requires complete observation through the matching horizon and has null delay plus the observed horizon length; never replace it with the horizon as if detection happened. Missing capture, inference, ground truth, or timing evidence makes the event `unobservable`. Publish these counts and the horizon alongside median/p95 delay among detected events; a detected-only average hides misses. Overlapping attack intervals require an explicit attribution rule before event-level reporting.

### Legitimate service availability and latency

The independent legitimate client must account for every actual request attempt. If retries are introduced, keep separate attempt IDs linked by `logical_request_id`; the current PR #7 client has no application retry loop. Record scheduled-but-unsent slots separately as workload gaps, not server failures. Define the endpoint, method, acceptable response codes, any payload check, timeout semantics and success predicate before a run. The [HTTP export mapping](#mapping-the-http-client-export) documents the existing client's limits.

- Availability = successful legitimate attempts / all legitimate attempts started in the reporting interval. Resolve those attempts to completion or an observed terminal outcome, including ones finishing after the interval ends. A real total-deadline policy additionally requires completion before that deadline; an HTTPX per-operation timeout does not establish a total deadline. The named initial predicate `http_get_status_2xx_v1` accepts a complete HTTP response with status 200-299; it cannot prove payload validation or a total response-time limit. Mujtaba confirmed this convention and Ayden accepted it during PR #7 review; see the mapping below.
- Evaluation outcomes are `success`, `timeout`, `connection_error`, `transport_error`, `invalid_response`, or `unknown`. Preserve raw outcomes separately. Unknown outcomes with a known attempted denominator make availability partial: report the unknown count and bounds `success/attempted` to `(success+unknown)/attempted`; the primary value stays null until outcomes are complete. If the attempted denominator itself is unknown, neither availability nor these bounds is established.
- Measure latency on the client's monotonic clock from actual request start to complete response. Use only attempts satisfying the reviewed success predicate; if it requires payload validation, the evidence must support that check. Report p50 and p95 plus success count. Report timeout, connection/other transport error and invalid-response counts/rates separately over all attempted requests. Failure duration is not successful-response latency.
- Proposed percentile method: nearest rank, sorted value at one-based index `ceil(p*n)` for `p=0.50` or `0.95`. Zero samples gives null; always show `n`. Use the same method across modes. Report pre-attack, attack, and post-attack intervals separately; interval lengths are TBD.

### False blocks and recovery

An alert or `block_requested` is not a block. Count a unique `block_id` only after independent firewall confirmation of an applied rule, and preserve confirmation and removal evidence. Repeated polls of the same active rule are not new blocks; a later confirmed removal and new installation creates a new action ID.

Proposed false-block measures:

- **False-block action fraction:** confirmed block actions against independently legitimate sources / confirmed actions against independently classified sources (legitimate or attack). Record unknown-source confirmed actions separately; the fraction is partial if any are unclassified. With no classifiable confirmed blocks it is null, even if the observed false-block count is zero.
- **Legitimate-source impact:** distinct independently legitimate sources that attempted traffic in the reporting interval and experienced a confirmed block during that interval / all distinct independently legitimate sources that attempted traffic in that interval. Report confirmed blocks of other legitimate sources separately; do not put sources outside the denominator population into the numerator. Evidence must establish those sources' role for the run; a spoofed address alone is insufficient. Zero legitimate sources gives null. Also report false-block count and confirmed blocked duration per legitimate source, bounded by the observation interval; unknown removal time gives a duration bound, not assumed expiry.

Recovery is proposed as the first post-onset evaluation interval in which legitimate availability meets an agreed target and successful-response p95 is at or below an agreed target for an agreed number of consecutive complete intervals. The targets, interval width, required request count, baseline reference, and consecutive count are all TBD. Keep missing/zero-request intervals ineligible. Report delay from attack onset, and separately from first confirmed block if present. Record `not_recovered` with complete observation length or `unobservable` with the missing evidence. Do not attribute improvement to blocking from timing alone. Confirmed block expiry/removal is a separate correctness check, not proof of service recovery.

### Process resources and monitoring overhead

Sample the detector/backend process tree using recorded PID plus process start identity; record children, restarts, host CPU count, sampler/tool version and interval. Proposed CPU convention: `100 * delta(process user+system CPU seconds) / delta(monotonic seconds)`, summed over the declared process set. One fully occupied core is 100%; multi-core totals may exceed 100%. Do not mix this with host-wide percentage. Missing samples/restarts without valid counter continuity produce null intervals.

Record resident set size (`rss_bytes`) for each process and the process-set sum; shared pages may be counted more than once, so this is not unique physical memory. Report time-weighted mean CPU and sampled peak CPU/RSS with sample count, covered duration, and gaps; a sampled peak is not a guaranteed instantaneous maximum. Keep collector and traffic-generator resources separate from detector resources. Use matched instrumented/uninstrumented calibration trials to estimate monitoring overhead before comparing modes; calibration and sampling frequency remain pending.

### Capture drops and measurement coverage

Preserve cumulative counter snapshots with source/tool, interface, exact counter name, scope, reset identity, timestamp, and documented semantics. Compute deltas only across continuous counters. Record capture-library/kernel drops, interface drops, malformed/truncated skips, and application queue losses separately. They may overlap or count different packet populations: never add them into a single loss number without verified semantics. The design's `skipped_packets` is a diagnostic skip count, not automatically a capture-drop counter. Preserve PR #8 normalization skip reasons separately as `non_ip`, `ipv6`, `truncated_header`, `bad_length`, and `unsupported_protocol`, with tool/version and scope. Keep destination-filter exclusions separate from malformed-packet skips. A packet with a valid IPv4 header may retain IP Total Length even when its captured payload is shorter; do not count all payload truncation as `truncated_header`. Unknown TCP flags do not imply zero observed flags; PR #8's `None` representation remains proposed.

Report a drop proportion only if the counter's documented denominator is known and compatible; record the numerator and denominator definitions. Otherwise report the counter delta with drop proportion null. Unsupported/unread counters are unknown, not zero. Observed capture packet rate is not offered traffic rate.

Window coverage = successfully observed/processed intervals (including verified quiet intervals) / expected intervals on the unix-epoch grid within the declared reporting bounds. Record how partial first/last intervals are excluded or qualified; epoch alignment alone does not establish their capture coverage. Assign each expected interval exactly one state and separately count failed, missing, and uncertain intervals; expected = valid + failed + missing + uncertain. Uncertain intervals are excluded from successful coverage. A gap is not a zero-traffic window. Keep per-window capture validity, dropped/skipped counts when attributable, and any uncertainty; capture loss may invalidate ground-truth labelling even when a feature row exists. Unknown health coverage prevents a full-coverage claim.

## Matched comparisons

Future runs compare `no_defense`, `monitor_only`, `rule_based`, and `ml_mitigation`. These names are evaluation conditions, not implemented CLI flags or new API modes. `monitor_only` requests no firewall operations; `ml_mitigation` would use the existing `automatic` policy only after all design prerequisites are met. The rule baseline and its settings still need definition.

Use matched topology/resources, legitimate workload, independently recorded attack workload, service settings, capture/window definition, label policy, model/data split, observation intervals, and instrumentation. Record differences explicitly. Use the same mitigation settings where comparable, reset and verify firewall state between runs, and record order/seed and repetition index. Trial count, run duration, order strategy, and statistical reporting need agreement before experimentation. In `no_defense`, classifier metrics are not applicable rather than zero. Preserve each trial and aggregate only comparable complete trials; never claim a performance improvement from this draft.

## Run-record format, version 0.2-draft

The JSON is a proposed collection format, not an executable JSON Schema or API change. Version `0.2-draft` replaces `window_origin_at` with `window_alignment`, adds `feature_schema_version`, distinguishes operation timeout from total deadline, and expands request rows for PR #7 provenance. Retain older records under their original version; this document does not automatically migrate them. Incompatible field/meaning changes require a version change. Required information can be filled progressively; finalizing a metric requires all of its evidence and prerequisites. `null` is allowed in the blank template and for unavailable values with an accompanying reason. Where one reason covers several fields, name those fields in the nearest `unavailable_reason`; never leave an unexplained null in a finalized metric.

Top-level identity fields are strings except `trial_index` (integer), `started_at`/`ended_at` (UTC strings), and `git_dirty` (boolean). `scenario_id` references the test plan, including `F01`-`F04`, `C01`-`C02`, or `L01`-`L09`. `scenario_checks` can record several checks within a run. `baseline_run_id` links the declared comparison baseline. `notes` is an array of strings, not measurement evidence.

The template pre-fills the approved epoch alignment and feature schema `"1"`, provisional label fraction `0.80`, and experimental model threshold `0.5`. These are planning baselines, not verified runtime settings or final Week 1 document sign-off. Verify the configuration used by each run and retain the applicable decision and artifact references. Other unknown fields remain null. Record the exact ordered `feature_names`, `feature_schema_version` and feature-schema artifact used by extraction and inference; a feature map alone does not preserve model input order. Store resolved environment/configuration dumps as hashed artifacts as well; an editable config file path alone is insufficient provenance. `mitigation_mode` follows the API (`monitor_only`/`automatic`) when a backend exists; otherwise use null. Do not populate it with the four evaluation-condition names.

The following tables define array row fields. `str`, `num`, `int`, `bool`, and `UTC` mean string, number, integer, boolean, and UTC timestamp; `?` permits null with a reason. IDs are unique within their array; referenced IDs must resolve. Every evidence-bearing row includes `artifact_ids: str[]` and `unavailable_reason: str?`. Use raw logs for detail and these rows for joins/calculation. Arrays remain empty in the committed template.

| Array | Row fields and meaning |
| --- | --- |
| `artifacts` | `artifact_id: str`, `kind: str`, `path: str`, `sha256: str?`, `bytes: int?`, `producer: str`, `tool_version: str?`, `collected_at: UTC?`, `unavailable_reason: str?`. Path is repository-relative or a controlled evidence URI; closed-file SHA-256 is required for final evidence. This array does not reference itself. |
| `clocks` | `clock_id: str`, `host_id: str`, `method: str`, `measured_at: UTC?`, `utc_offset_seconds: num?`, `uncertainty_seconds: num?`, `valid_from: UTC?`, `valid_until: UTC?`, plus evidence fields. Offset convention: corrected UTC = recorded host time + offset. Cross-host comparisons require valid bounds for both clocks. |
| `sources` | `source_id: str`, `source_ip: str?`, `host_id: str?`, `role: str` (`legitimate`, `attack`, `unknown`), `role_valid_from: UTC?`, `role_valid_until: UTC?`, `identity_basis: str`, plus evidence fields. Do not classify a spoofed address from generator intent alone. |
| `generator_intervals` | `interval_id: str`, `source_ids: str[]`, `kind: str` (`legitimate`/`attack`), `protocol: str`, `target: str`, `start_at: UTC?`, `end_at: UTC?`, `clock_id: str`, `independently_confirmed: bool`, `offered_count: int?`, `offered_unit: str?`, plus evidence fields. These are observed generator intervals, not predictions. |
| `requests` | `request_id: str`, `logical_request_id: str`, `source_id: str?`, `client_run_id: str?`, `request_index: int?`, `started_at: UTC`, `epoch_seconds: num?`, `deadline_at: UTC?`, `completed_at: UTC?`, `clock_id: str?`, `raw_outcome: str?`, `error_type: str?`, `elapsed_attempt_seconds: num?`, `outcome: str`, `latency_seconds: num?`, `response_code: int?`, `success_predicate_id: str?`, plus evidence fields. Source/clock identity and predicate may be missing on import, but relevant final metrics require them. Preserve failure durations separately from successful latency. Nullable completion/deadline fields must not be fabricated from an operation timeout. See the export mapping below. |
| `windows` | `window_id: str`, `start_at: UTC`, `end_at: UTC`, `clock_id: str`, `capture_state: str` (`valid`, `failed`, `missing`, `uncertain`), `selected_packets: int?`, `attack_labelled_packets: int?`, `unknown_packets: int?`, `label: str` (`attack`, `benign`, `excluded`), `label_reason: str`, `label_policy_id: str?`, `features: object?` (the exact configured feature names mapped to finite numeric values when available), `split: str` (`train`, `validation`, `test`, `lab`), `generator_interval_ids: str[]`, plus independent evidence fields. Use the agreed origin; count label exclusions by reason. |
| `predictions` | `prediction_id: str`, `window_id: str`, `aggregate_detection_id: str?`, `inference_at: UTC`, `clock_id: str`, `predicted_attack: bool`, `attack_score: num?`, `decision_threshold: num?`, `model_version: str?`, plus evidence fields. Negative predictions are required even if the API emits no detection record. |
| `detection_matches` | `interval_id: str`, `status: str` (`detected`, `not_detected`, `unobservable`), `prediction_id: str?`, `observation_end_at: UTC?`, `observed_horizon_seconds: num?`, `delay_seconds: num?`, `delay_lower_seconds: num?`, `delay_upper_seconds: num?`, `timing_uncertain: bool`, plus evidence fields. One row per confirmed attack interval; ID resolves the matching window through its prediction. |

| Array | Row fields and meaning |
| --- | --- |
| `mitigation_events` | `event_id: str`, `block_id: str`, `source_id: str?`, `source_ip: str`, `attribution_detection_id: str?`, `event_type: str` (`requested`, `confirmed_applied`, `request_failed`, `confirmed_removed`, `removal_failed`, `reconciled_active`), `observed_at: UTC`, `clock_id: str`, `planned_expires_at: UTC?`, `firewall_rule_id: str?`, plus evidence fields. Preserve actual firewall evidence for confirmed states; planned expiry is not removal. |
| `process_samples` | `sample_id: str`, `process_id: int`, `process_start_id: str`, `component: str`, `host_id: str`, `observed_at: UTC`, `monotonic_seconds: num`, `cpu_user_seconds: num?`, `cpu_system_seconds: num?`, `rss_bytes: int?`, plus evidence fields. Cumulative CPU values support deltas without confusing restarted PIDs. |
| `capture_health` | `health_id: str`, `interface: str`, `start_at: UTC`, `end_at: UTC`, `expected_windows: int?`, `valid_windows: int?`, `failed_windows: int?`, `missing_windows: int?`, `uncertain_windows: int?`, `counter_snapshots: object[]`, plus evidence fields. Each snapshot has `counter_name: str`, `source: str`, `scope: str`, `reset_id: str`, `observed_at: UTC`, `value: int?`, `semantics: str`, `denominator_counter_name: str?`, `unavailable_reason: str?`. Preserve cumulative values; do not treat reset differences as negative loss. |
| `recovery_intervals` | `interval_id: str`, `attack_interval_id: str`, `start_at: UTC`, `end_at: UTC`, `attempted: int?`, `successful: int?`, `unknown_outcomes: int?`, `availability: num?`, `p95_latency_seconds: num?`, `complete: bool`, `meets_targets: bool?`, plus evidence fields. Targets must reference reviewed configuration before `meets_targets` is set. |
| `metric_results` | `metric_id: str`, `population: str`, `interval_start: UTC?`, `interval_end: UTC?`, `value: num?`, `unit: str`, `numerator: num?`, `denominator: num?`, `sample_count: int?`, `status: str` (`available`, `partial`, `unavailable`, `not_applicable`), `reason: str?`, `input_ids: str[]`, `artifact_ids: str[]`. Ratios use proportions; counts use `count`; durations use `seconds`. Include confusion counts and exclusions as separate metric rows. Input references use `array_name:id` and must resolve. |
| `scenario_checks` | `check_id: str`, `scenario_id: str`, `status: str` (`not_run`, `blocked`, `passed`, `failed`), `reason: str?`, `artifact_ids: str[]`. Evidence is required for a pass/fail decision; pending implementation is blocked. |

For large experiments, the arrays may be stored in hashed JSON/JSONL artifacts using the same row fields; record that choice and file-to-array mapping in `external_rows`. Each mapping has `array_name: str`, `artifact_id: str`, `format: str` (`json`/`jsonl`), and `row_count: int`. Use either inline rows or one external mapping for an array, never both, and do not sample away failed requests or missing windows.

Before accepting a record, check JSON parsing, unique IDs and reference resolution, timestamp ordering and clock bounds, nonnegative counts and monotonic elapsed durations, snapshot counter continuity, hashes, metric denominators, and raw-evidence coverage. Negative cross-host delay estimates are retained only with the timing-uncertainty flag and evidence described above; they are not valid precise delay claims. Check that no null was converted to zero and that the matrix counts equal the evaluable window count. Final records must distinguish test failure, observation failure, and tests that were never run. This proposal has no automated validator yet.

## Mapping the HTTP client export

This mapping was checked against [PR #7](https://github.com/aydsman/ML-DDoS-Detector/pull/7), head `430a629ed849d3ea6cbe9f4d7c66d2f651535910`, now merged into `development`. Its issue #13 changes first appeared in `4bcb64a`; `ba6a521` is the older review/lab revision, not the current mapping baseline. Preserve the generating commit for each artifact because additive fields changed within `draft-2`.

[Mujtaba's component-side agreement](https://github.com/aydsman/ML-DDoS-Detector/pull/9#issuecomment-6478498003) confirms the client/experiment ID association, `http:<client_run_id>:<request_index>` identity, status-only 2xx predicate, milliseconds-to-seconds conversion, operation-timeout semantics and independent ground truth. Ayden took over Ali's outstanding review on November 2, independently checked the current client and accepted these W1 conventions in [PR #7](https://github.com/aydsman/ML-DDoS-Detector/pull/7). This is Ayden's review, not a claim that Ali personally reviewed it. Final review of the refreshed PR #9 remains requested. Actual generator logs, source/clock evidence, trial settings and later performance criteria remain pending.

Paced mode exports `run.json` with schema `draft-2` and `requests.csv`. Keep both unchanged as hashed artifacts. The exact CSV columns are `run_id,request_index,started_at,epoch_seconds,elapsed_ms,outcome,status_code,error_type`. Parse empty status/error fields as null, never zero. Single-request mode cannot produce these exports. Preserve older `draft-1` exports under their own schema.

| Export field | Run-record mapping | Meaning / limit |
| --- | --- | --- |
| `run_id` | Preserve as `client_run_id`; record its association with the enclosing experiment `run_id` in the workload artifact. | The client generates its own UUID and has no shared-ID CLI argument. Do not assume detector/client IDs match. A single-client experiment can deliberately adopt this UUID, with that choice recorded. |
| `request_index` | Preserve it; derive `request_id = http:<client_run_id>:<request_index>`. For this client, `logical_request_id = request_id`. | One-based scheduled-slot index, not a contiguous attempt count. Gaps may be skipped/cancelled slots. Live rows are completion-ordered; orderly finalization rebuilds them in dispatch order. Use identities, never row position. One GET per attempt, no application retry loop. |
| `started_at`, `epoch_seconds` | Copy both; verify consistency. | Both describe the same UTC request start sampled inside the worker. Epoch seconds are parsed from `started_at`, not independent timing evidence. They support the approved epoch grid but cannot establish cross-host synchronization. |
| `elapsed_ms` | `elapsed_attempt_seconds = elapsed_ms / 1000`; use as `latency_seconds` only for successful attempts under the reviewed predicate. | Monotonic duration around the GET, through body receipt or caught failure. Excludes executor scheduling delay. Failure duration is not successful-response latency. |
| `status_code` | `response_code` | 404/503 remain HTTP responses in the raw log; a missing code is not status 0. |
| `outcome`, `error_type` | Preserve as `raw_outcome`, nullable `error_type`; derive evaluation `outcome` separately using the table below. | Keep raw exception classes and source artifact references. |
| `settings.target` | Record endpoint and method GET in the workload/predicate artifact. | No content-check evidence or success-predicate ID is exported. Redirects are not followed. |
| `settings.timeout_seconds` | `configuration.request_operation_timeout_seconds`, with `request_timeout_semantics: "httpx_per_operation"` | Applies to connect/read/write/pool operations. It is not a total deadline: leave `request_total_deadline_seconds` and request `deadline_at` null unless a separate real policy supplies them. |
| `settings.request_rate`, `duration_seconds`, `concurrency` | Preserve exact settings in the workload artifact. | Rate is scheduled requests/s, not packet rate; duration limits request starts, while in-flight requests may finish later. Concurrency limits active requests and does not multiply the configured rate. |
| `summary.scheduled_slots`, `attempted`, `skipped_due_to_lag`, `skipped_due_to_capacity`, `skipped_at_deadline`, `cancelled_slots` | Preserve the full workload ledger with generating commit in the workload artifact. | Scheduled slots equal attempts plus the three skip categories plus cancellations. Missing counters in older exports are unknown, never zero. |
| JSON `state`, `summary` | Retain as completeness evidence, distinct from test status. | `complete` can include HTTP failures. `running` with null summary may be a crash remnant; `interrupted` is not a completed intended-duration run. |

### Raw outcomes and the success predicate

| Raw client outcome | Evaluation treatment |
| --- | --- |
| `http_response`, status 200-299 | `success` under the initial `http_get_status_2xx_v1` predicate. The client's `successful_2xx` count does not prove payload validation or a total deadline. If stronger criteria are required, this export alone leaves that success unknown. |
| `http_response`, other status | `invalid_response` under the initial 2xx predicate; retain the actual status. A redirect is not a followed successful response. |
| `timeout` | `timeout`; retain the HTTPX exception class. Total elapsed time may exceed the operation-timeout setting. |
| `request_error` | `transport_error`; retain the class. HTTPX request errors include more than connection failures, so use `connection_error` only when the specific evidence establishes that subtype. |
| `interrupted` | `unknown`, reason `client_interrupted`; this is not a verified server failure or timeout. |
| `unexpected_error` | `unknown`, retaining the exception class; an instrumentation/client error does not establish service success or failure. |

Use `success_predicate_id: "http_get_status_2xx_v1"` only when the experiment explicitly adopts this initial legitimate-GET convention, and retain the endpoint/method and review references. Availability and successful-response latency still require reconciled request evidence, source/clock context and missing-data accounting. Any stronger content/deadline-based metric requires additional evidence. These definitions do not add columns or validation to the client itself.

### Skips, completeness and missing evidence

Current exports retain the complete workload ledger:

```text
scheduled_slots = attempted + skipped_due_to_lag + skipped_due_to_capacity
                  + skipped_at_deadline + cancelled_slots
```

`scheduled_slots` counts half-open fixed-grid points before the deadline. On normal completion, all missed tail slots from response overrun or scheduler oversleep count as lag; cancellations are zero. On intentional interruption, unsent/unvisited remaining slots count as cancellations, distinct from ordinary lag and delayed-worker deadline skips. A request that starts and is interrupted is still an attempt with an unknown outcome. Skips/cancellations have no request CSV row and never enter the service-failure denominator. Retain the separate counters; they do not reconstruct every slot's actual dispatch time or per-window offered load.

The `scheduled_slots` and `cancelled_slots` fields are additive within `draft-2`. Older exports may lack them and may undercount tail skips. Preserve schema plus generating commit; leave missing fields unknown with a reason, never substitute zero or silently rewrite old lab artifacts.

`summary.attempted` counts completed result records at orderly finalization. Achieved rate divides that count by actual elapsed run time including in-flight completion, not the configured request-start duration. Before a finished JSON summary is published, finalization rebuilds CSV from completed records into a temporary file, closes the old handle and atomically replaces the CSV. This repairs missed/partial incremental writes at the interruption boundary and remains duplicate-free on repeated finalization. Live consumers must reopen the CSV after finalization; identify requests by `(client_run_id, request_index)`.

Reconcile state, summary attempt count, unique indices, row identities, outcomes and the workload ledger before using results. An orderly `interrupted` export can reconcile completed attempts without representing the full intended-duration trial. A crash, failed reconciliation or `running`/null-summary artifact remains incomplete: flushed rows do not establish every actual attempt or a known full-run denominator. Report observed rows and missing coverage honestly.

The experiment collector must additionally obtain:

- **Timing:** source/clock identity, offsets and uncertainty, actual observation bounds. Run UTC `started_at` is recorded before export initialization, while the pacing timer starts afterward; it is not the exact scheduling origin. No actual run end or request `completed_at` is exported. Leave completion UTC null rather than treating wall-clock start plus monotonic duration as an exact measured timestamp.
- **Identity and ground truth:** source IP/host/role evidence, experiment-to-client ID mapping, independent attack-generator intervals and actual activity. HTTP results do not supply packet attack labels or detection-delay ground truth.
- **Success and coverage:** reviewed predicate, any content/total-deadline evidence, and durable start/dispatch records if complete accounting must survive crashes. Aggregate skip counts alone do not show per-window offered load.
- **Provenance:** tested Git/runtime/dependency versions, hashes, detector/capture/firewall/resource records and actual configuration. Client settings alone do not prove matched received traffic across runs.

Leave missing imported `source_id`, `clock_id`, `success_predicate_id`, completion/deadline and timing values null with field-specific reasons. These rows can be retained for review, but final metrics require their applicable identity, predicate, timing and coverage evidence.


## Review needed before live collection

| Reviewer | Decision/evidence needed |
| --- | --- |
| Mujtaba + Ali | W1 client/experiment mapping and initial 2xx predicate are recorded above (Mujtaba agreement, Ayden review). Still needed for live collection: source IDs, actual generator start/end logs, workload schedule, trial duration/order/repetitions, recovery intervals and complete legitimate-client evidence. |
| Vince + Ali | Actual capture interface/filter and interval coverage on the approved epoch grid; counters by reason and clock bounds; adapter parity and coverage using the merged normalization/None-flags baseline; verified dataset metadata/checksums/splits, boundary exclusions, independent labels and sensitivity to provisional X = 0.80. |
| Ayden + Ali | Per-window positive and negative inference logs and window IDs; model/threshold provenance; attribution links; firewall confirmation/removal evidence; policy settings; measurable acceptance and recovery targets. |
| Aadi + Ayden | UI history limits, stale/error/empty states and polling overhead; evidence that displayed values reference the retained backend records. Dashboard screenshots supplement raw logs but cannot supply metric denominators. |

Review references belong in the record's `decisions` object. Until these decisions and implementations exist, the files support W1 planning and do not demonstrate model accuracy, availability, latency, mitigation, or recovery.
