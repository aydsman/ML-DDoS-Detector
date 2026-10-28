# Measurement definitions and run records

Status: W1 draft for component-owner review. Owner: Ali. This document defines proposed experiment records and calculations; it contains no experiment results or agreed performance targets. See the [test plan](test-plan.md), [design](design.md), [API contract](api-contract.md), and unresolved decisions in [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5). The design remains authoritative for detection, labels, and enforcement.

## Collection rules

- Copy [the blank run record](templates/run-record.template.json) to `results/<run_id>/run-record.json`. Keep generated records/results in gitignored `results/`, raw logs in `logs/`, and captures/datasets in `data/`. Commit only the blank template and documentation.
- Replace `record_type: "template"` with `"experiment"` only for an actual run. Use a unique `run_id`; link matched trials with `comparison_id`. A planned run may still have `status: "not_run"`. Test statuses are `not_run`, `blocked`, `passed`, or `failed`; passing requires the scenario's stated evidence. These are test results, not service health states.
- Use UTC ISO 8601 timestamps ending in `Z`, seconds for durations, bytes for memory, and numeric proportions from 0 to 1. Intervals are `[start, end)`. Retain original timestamps/timezone and conversion evidence in the source artifact.
- `null` means unknown, unavailable, or not applicable; provide a reason. Zero means a measured zero. Empty arrays in the template mean no records collected, not proof that no attacks, failures, or blocks occurred.
- Preserve raw evidence, collection commands/tool versions, Git commit and dirty state, resolved package versions, configuration, model/dataset references, and SHA-256 hashes. Calculate hashes after files are closed. Do not place secrets in the record.
- Independently establish traffic labels from verified dataset metadata or generator identities, protocol, target, and actual start/end logs. Detector scores, alert decisions, firewall actions, and assumed schedules are never ground truth.
- Use one record per aggregate window. Label threshold `X` is still unresolved; 80% is a suggestion, not an approved value. Keep the threshold and approval reference null until agreed. Apply the design's mixed, unknown, boundary, empty, and zero-confirmed-attack exclusions; record each reason and count. No headline label-based metrics are valid until the label rule and evidence are reviewed.

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

The independent legitimate client records every actual request attempt, including retries as separate attempts linked by `logical_request_id`. Record scheduled-but-not-sent attempts separately as generator failures; they are not server failures. Define the endpoint, method, payload check, acceptable response codes, timeout, and success predicate before a run.

- Availability = successful legitimate attempts / all legitimate attempts started in the reporting interval. Count an attempt as successful only if it meets the recorded predicate before its deadline. Resolve attempts through their deadline even if they finish after the interval ends.
- Outcomes are `success`, `timeout`, `connection_error`, `invalid_response`, or `unknown`. Unknown outcomes make availability partial: report unknown count and bounds `success/attempted` to `(success+unknown)/attempted`; the primary value stays null until outcomes are complete.
- Measure latency on the client's monotonic clock from send/start to validated complete response. Report p50 and p95 for successful attempts only, plus success count. Report timeout count/rate, connection-error count/rate, and invalid-response count/rate separately, each over all attempted requests. Never enter a timeout deadline as a successful latency.
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

Preserve cumulative counter snapshots with source/tool, interface, exact counter name, scope, reset identity, timestamp, and documented semantics. Compute deltas only across continuous counters. Record capture-library/kernel drops, interface drops, malformed/truncated skips, and application queue losses separately. They may overlap or count different packet populations: never add them into a single loss number without verified semantics. The design's `skipped_packets` is a diagnostic skip count, not automatically a capture-drop counter.

Report a drop proportion only if the counter's documented denominator is known and compatible; record the numerator and denominator definitions. Otherwise report the counter delta with drop proportion null. Unsupported/unread counters are unknown, not zero. Observed capture packet rate is not offered traffic rate.

Window coverage = successfully observed/processed intervals (including verified quiet intervals) / expected intervals on the explicit capture origin and reporting grid. Assign each expected interval exactly one state and separately count failed, missing, and uncertain intervals; expected = valid + failed + missing + uncertain. Uncertain intervals are excluded from successful coverage. A gap is not a zero-traffic window. Keep per-window capture validity, dropped/skipped counts when attributable, and any uncertainty; capture loss may invalidate ground-truth labelling even when a feature row exists. Unknown health coverage prevents a full-coverage claim.

## Matched comparisons

Future runs compare `no_defense`, `monitor_only`, `rule_based`, and `ml_mitigation`. These names are evaluation conditions, not implemented CLI flags or new API modes. `monitor_only` requests no firewall operations; `ml_mitigation` would use the existing `automatic` policy only after all design prerequisites are met. The rule baseline and its settings still need definition.

Use matched topology/resources, legitimate workload, independently recorded attack workload, service settings, capture/window definition, label policy, model/data split, observation intervals, and instrumentation. Record differences explicitly. Use the same mitigation settings where comparable, reset and verify firewall state between runs, and record order/seed and repetition index. Trial count, run duration, order strategy, and statistical reporting need agreement before experimentation. In `no_defense`, classifier metrics are not applicable rather than zero. Preserve each trial and aggregate only comparable complete trials; never claim a performance improvement from this draft.

## Run-record format, version 0.1-draft

The JSON is a proposed collection format, not an executable JSON Schema or API change. Incompatible field/meaning changes require a version change. Required information can be filled progressively; finalizing a metric requires all of its evidence and prerequisites. `null` is allowed in the blank template and for unavailable values with an accompanying reason. Where one reason covers several fields, name those fields in the nearest `unavailable_reason`; never leave an unexplained null in a finalized metric.

Top-level identity fields are strings except `trial_index` (integer), `started_at`/`ended_at` (UTC strings), and `git_dirty` (boolean). `scenario_id` references the test plan, including `F01`-`F04`, `C01`-`C02`, or `L01`-`L09`. `scenario_checks` can record several checks within a run. `baseline_run_id` links the declared comparison baseline. `notes` is an array of strings, not measurement evidence.

Configuration objects in the template preserve the exact run settings and review references. Record the exact ordered `feature_names` and feature-schema artifact used by extraction and inference; a feature map alone does not preserve model input order. Store resolved environment/configuration dumps as hashed artifacts as well; an editable config file path alone is insufficient provenance. `mitigation_mode` follows the API (`monitor_only`/`automatic`) when a backend exists; otherwise use null. Do not populate it with the four evaluation-condition names.

The following tables define array row fields. `str`, `num`, `int`, `bool`, and `UTC` mean string, number, integer, boolean, and UTC timestamp; `?` permits null with a reason. IDs are unique within their array; referenced IDs must resolve. Every evidence-bearing row includes `artifact_ids: str[]` and `unavailable_reason: str?`. Use raw logs for detail and these rows for joins/calculation. Arrays remain empty in the committed template.

| Array | Row fields and meaning |
| --- | --- |
| `artifacts` | `artifact_id: str`, `kind: str`, `path: str`, `sha256: str?`, `bytes: int?`, `producer: str`, `tool_version: str?`, `collected_at: UTC?`, `unavailable_reason: str?`. Path is repository-relative or a controlled evidence URI; closed-file SHA-256 is required for final evidence. This array does not reference itself. |
| `clocks` | `clock_id: str`, `host_id: str`, `method: str`, `measured_at: UTC?`, `utc_offset_seconds: num?`, `uncertainty_seconds: num?`, `valid_from: UTC?`, `valid_until: UTC?`, plus evidence fields. Offset convention: corrected UTC = recorded host time + offset. Cross-host comparisons require valid bounds for both clocks. |
| `sources` | `source_id: str`, `source_ip: str?`, `host_id: str?`, `role: str` (`legitimate`, `attack`, `unknown`), `role_valid_from: UTC?`, `role_valid_until: UTC?`, `identity_basis: str`, plus evidence fields. Do not classify a spoofed address from generator intent alone. |
| `generator_intervals` | `interval_id: str`, `source_ids: str[]`, `kind: str` (`legitimate`/`attack`), `protocol: str`, `target: str`, `start_at: UTC?`, `end_at: UTC?`, `clock_id: str`, `independently_confirmed: bool`, `offered_count: int?`, `offered_unit: str?`, plus evidence fields. These are observed generator intervals, not predictions. |
| `requests` | `request_id: str`, `logical_request_id: str`, `source_id: str`, `started_at: UTC`, `deadline_at: UTC`, `completed_at: UTC?`, `clock_id: str`, `outcome: str`, `latency_seconds: num?`, `response_code: int?`, `success_predicate_id: str`, plus evidence fields. Outcome values and monotonic latency rules are defined above. |
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

## Review needed before live collection

| Reviewer | Decision/evidence needed |
| --- | --- |
| Mujtaba + Ali | Shared run/source IDs; actual generator start/end logs; request success predicate, retries/timeouts and outcomes; workload schedule; trial duration/order/repetitions; recovery intervals and legitimate-client evidence. |
| Vince + Ali | Capture interface/origin/empty-window handling; counter meanings and clock bounds; packet normalization; dataset metadata/checksums/splits; label threshold, boundary exclusions and inspectable independent label sample. |
| Ayden + Ali | Per-window positive and negative inference logs and window IDs; model/threshold provenance; attribution links; firewall confirmation/removal evidence; policy settings; measurable acceptance and recovery targets. |
| Aadi + Ayden | UI history limits, stale/error/empty states and polling overhead; evidence that displayed values reference the retained backend records. Dashboard screenshots supplement raw logs but cannot supply metric denominators. |

Review references belong in the record's `decisions` object. Until these decisions and implementations exist, the files support W1 planning and do not demonstrate model accuracy, availability, latency, mitigation, or recovery.
