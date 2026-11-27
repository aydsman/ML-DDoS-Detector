# Week 5 evaluation and model-selection handoff

Prepared by Ayden November 24; status updated November 26, 2026. **Preparation reviewed; final release withheld.** Ali approved the candidate rationale and guarded classifier-evaluation method in PR #52. Ayden completed the draft report-use review as owner under the user's instruction; this is not Aadi's approval. Aadi still assembles the report, and Vince supplies lab feasibility/evidence. Integrated trial/recovery parameters below remain proposals. No final evaluation is complete.
The candidate inventory is [week5-model-candidates.json](week5-model-candidates.json).

## What is ready

- Controlled-lab S1 training, S2 validation and untouched S3 assignments are
  documented in [the baseline](week2-pilot-baseline.md). PRs #42 and #44 are
  merged. Neither public CIC acceptance nor mitigation accuracy is implied.
- The existing forest, comparison MLP/scaler, original metadata and S2 reports
  have fixed SHA-256 identities. The proposed candidate inventory records all
  eight input/package/report hashes and the ordered twelve features.
- The [ML contribution](contributions/ayden-ml-methodology.md), S2 comparison and
  [laptop timing evidence](reviews/inference-benchmark-2026-11-21.json) are prepared.
- Trained-model benign live API integration is accepted in
  [the monitor record](monitor.md#trained-model-live-acceptance-reviewed-november-22).
  The automatic runner/dashboard integration remains separate.

The candidate file is deliberately status=proposed with approval_ref=null.
Writing down hashes freezes the identity of a proposal, not deployment approval.
No model or threshold changed and no S3 model outcomes were inspected here.

## Model recommendation for Ali's review

Retain the saved 100-tree Random Forest at threshold 0.5 as the primary
integration candidate. Its trusted package, loader and live monitor/API path
have already been exercised with real benign traffic. The scaled 16-unit MLP
at threshold 0.5 remains the comparison candidate. The aggregate rate rule
retains the S1-derived strict cutoff packet_rate > 42 packets/s.

RF and MLP each have 300 TN / 250 TP / 0 FP / 0 FN on the same 550 eligible S2
windows. This tie on one narrow session does not establish accuracy superiority.
The MLP is faster in the recorded laptop benchmark (median 1.162 ms versus
21.807 ms); do not describe the RF as the faster model or extrapolate those
timings to the VM. The RF recommendation favors the existing integration path,
not a claim of optimal accuracy, latency or generalization. Ali may challenge
it before release. No live MLP deployment adapter is introduced by this plan.

Record the primary choice and the exact candidate set **before** viewing S3.
The held-out comparison reports all three frozen methods in one release.
Do not select new settings or switch the deployed model based on S3. If results
are disappointing, report them; a later revised model needs new unseen data.

## Release checklist: classifier evaluation

Ayden supplies the candidate identities and command; Ali independently reviews
the method and supplied data evidence. Ayden has checked that the draft report separates validation, final-test and live-system claims. Aadi remains responsible for report assembly; final results will require a later review.

- [x] Ali reviewed the S1/S2 evidence, rationale, candidate set and thresholds: [independent review](https://github.com/aydsman/ML-DDoS-Detector/pull/52#pullrequestreview-6083217879). This approves preparation, not release.
- [ ] Confirm the reviewed labels, exclusions and independent session assignments.
      The existing S3 inventory is known; no additional model-score inspection
      is needed for this check.
- [x] Confirm exact input/model bytes and compatible runtime with the candidate file: [November 26 owner verification](reviews/week5-owner-verification-2026-11-26.json), all eight sources and staged copies match. Original files are unchanged.
- [ ] Decide whether the system's classifier choice is final before revealing S3.
      If policy tuning in #50 could change that choice, keep S3 withheld.
- [ ] Record the actual review reference; make a reviewed local copy of the
      candidate JSON with status=approved. Do not approve by filling a fake ID.
- [ ] Record who will run the one planned evaluation, its tested revision,
      environment and fixed fresh output path. Check that nobody has already
      run it. Copy/rename paths can bypass local guards; the team owns this ledger.
- [ ] After the run, preserve all outcomes, exclusions, input/package/configuration
      identities and raw output outside Git. Publish bounded metrics with review.
- [ ] Aadi accepts the resulting architecture/ML section with its limitations.

The offline classifier release can be reviewed while #49/#50 are pending,
but it is not authorization for policy or live-system evaluation. This branch
does not release it or claim the team has agreed.

## Prepared final-classification command

tools.evaluate_frozen_models checks explicit confirmation and the approved
freeze before reading the dataset or loading either estimator. It checks all
eight artifact hashes, established Python-major/minor and exact ML versions,
model identity and the saved validation choices. It never fits a model,
searches thresholds or predicts on training/validation rows. Synthetic fixtures
need an explicit --allow-synthetic; do not use that flag for the reviewed lab.

After the release checklist is signed off, activate the project Python 3.12
environment and run from the repository root. The paths below are example
local staging locations, not files committed to Git. Retain original filenames
and hashes when staging them; create the results/week5 parent directory first.

~~~sh
python -m tools.evaluate_frozen_models --records data/reviewed-windows.json --manifest data/reviewed-splits.json --forest results/week2-model --comparison results/week4-comparison --freeze results/week5/approved-model-candidates.json --output results/week5/final-classification.json --confirm-final-test
~~~

The committed proposed JSON is intentionally rejected. The command exclusively
creates a new output, but it cannot prevent an operator from rerunning with a
different path or fabricated approval. Run once under the agreed ledger.
Do not rerun merely to improve results. A failed attempt must be retained and
reviewed before deciding whether any restart compromises the held-out test.

The evaluator returns each method's test confusion matrix, accuracy, attack
precision/recall/F1, benign false-positive rate, actual denominators, exclusions
and window scores. Undefined denominators stay null. These are correlated
eligible windows from one session, not independent attack trials; do not attach
an unjustified narrow confidence interval or broad benchmark claim.

## Final result tables to complete after evidence exists

The following entries are intentionally not measured.

| Report item | Required result | Current status |
| --- | --- | --- |
| RF S3 classification | TN/FP/FN/TP, precision/recall/F1, benign FPR, eligible counts/exclusions | Not run |
| MLP S3 classification | Same exact S3 population and frozen threshold | Not run |
| Aggregate rule S3 classification | Same population, unchanged strict S1-derived cutoff | Not run |
| VM scoring cost | Hardware/runtime, batch-size-one median/p95, repetitions and scope | Not measured here |
| Full-system service/mitigation | Matched per-trial outcomes below | Blocked by W4 acceptance |
| Capture/resource coverage | Counter sources, population, gaps, process identity and timestamps | Incomplete |

## Separate integrated experiment proposal for Ali

This is Ali's experiment ownership, with Ayden supplying model/policy identities,
Vince supplying lab/capture/environment evidence and Mujtaba supplying generator,
enforcement and reset records. It adds no new traffic generator or lab capability.

Compare no defense, monitor-only, simple-rule mitigation and ML mitigation
under matched topology, resources, actual offered workloads and instrumentation.
The aggregate rate classifier above is **not** automatically the operational
simple-rule mitigation mode: its source attribution/allowlist/threshold behavior
must be independently specified before that mode can be compared.

Propose at least three independent repetitions for each supported SYN/UDP
scenario and mode. Rotate mode order using a recorded seed (3670 proposed),
and retain warm-up, failed and excluded trials. Proposed phases are 30 seconds
pre-onset, 60 seconds attack and 90 seconds observation/recovery, with verified
reset before each trial. These are review proposals, not agreed durations.
Calibrate feasible loads first: the prior HTTP request setting of 5/s achieved
about 1.6-2.5/s, so configured rates alone cannot establish matched conditions.

Use [measurement-formats.md](measurement-formats.md) for definitions:
- Classification uses reviewed window labels and denominators, not HTTP failures.
- Detection delay uses independently recorded attack onset and actual first alert;
  retain clock-offset uncertainty and any unobservable trial.
- Block delay uses firewall-confirmed installation, not request creation.
- Availability is successful 2xx / completed attempted requests for a declared
  interval; keep scheduled/skipped/missing outcomes separate.
- Latency p50/p95 uses nearest rank over successful responses with sample count;
  errors/timeouts remain explicit. This differs from the existing NumPy
  percentile convention in the model-only timing benchmark; label each method.
- False blocks need source role evidence and confirmed block/removal intervals.
  An allowlisted client's zero blocks alone cannot establish general source-level
  false-positive performance. Restrict the conclusion if other legitimate
  source evidence is unavailable.
- Proposed recovery: three consecutive complete 10-second intervals, at least
  ten attempted requests each, availability >=95% and successful-response p95
  <=2 times the matched pre-attack baseline. Ali must review these proposals
  after workload calibration. Missing requests/baseline/clock coverage means
  unobservable, not recovered.
- Resource reports retain the detector process tree/start identity, sampling
  interval, core-normalized convention, RSS and missing samples. Keep generator
  and collector resources separate.
- Capture/socket/interface counters retain their distinct scopes. Unknown loss
  stays unknown; never add overlapping counters into invented total-path loss.

## Integrated release gate and review queue

No new live experiment is run by this work. The blocking policy remains
monitor-only, with null unvalidated settings.

| Input / decision | Owner | Gate |
| --- | --- | --- |
| New policy-calibration/validation diagnostics and provenance, #49 | Vince | Exporter corrections and new recordings pending; original S1/S2/S3 unchanged |
| Combined model-gated policy/three-window validation, #50 | Ayden; Ali reviews evidence | Blocked by #49 |
| Runtime scope/allowlist and lifecycle acceptance, #51/#47 | Vince and Mujtaba; Ayden accepts | Blocked by #50 |
| Independent current start/stop runbook check, #41 | Lab-capable reviewer | Pending |
| Accepted enforcement events displayed truthfully | Ayden/Aadi | Pending integration |
| Trial schedule/load/recovery targets and actual calibration | Ali with Vince/Mujtaba | Proposed above; not approved |
| Draft report-use review and final assembly | Ayden reviews own contribution; Aadi assembles; Ali reviews evidence | Owner draft review complete; final results/assembly pending |

Each completed trial needs comparison/run IDs, phase boundaries, independent
source/attack evidence, model/configuration hashes, actual HTTP/scenario exports,
capture/health/policy/firewall evidence and tool/runtime revisions. No-defense
classifier metrics are not applicable. Unsupported modes or missing data are
reported as blocked/unobservable, never fabricated as passing.

## Handoff to Aadi

Use the current [ML contribution](contributions/ayden-ml-methodology.md) for
architecture/features/splits, S2 comparison, local scoring cost, accepted benign
live integration and limitations. Keep S2 validation and future S3 results in
separate tables. The existing capture pilot is controlled-lab data; CIC issue #3
remains unresolved. Describe policy code and actual firewall outcomes separately.
Mock UI values and the benign live plumbing check are not attack-accuracy results.

Review this PR for the report structure and missing evidence; use it as a draft
handoff rather than waiting for Week 4 to fill every result table. Final results,
model adoption and report acceptance remain pending.


## November 26 staging and owner review

All eight candidate artifacts were copied into a fresh ignored staging directory and rehashed. Runtime versions and saved metadata/threshold links match; the proposed freeze still refuses release. [Owner handoff and remaining gates](week5-owner-review.md). This did not deserialize estimators, invoke predictions or score S3. The global single-run ledger is not yet confirmed.
