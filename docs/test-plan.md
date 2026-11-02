# Test plan and acceptance checks

Owner: Ali (QA and Performance Engineer). Status: **draft for Week 1 review**.

Task: [W1 — Define the test plan and measurement formats](https://trello.com/c/dSv2o6Fu), planning deadline October 28, 2026, 5 p.m. America/Toronto.

This plan defines what to check and what evidence to keep. It is not an experiment report. A listed scenario is not evidence that it has run or passed.

## Scope and source of requirements

Use the [design](design.md) and [API contract](api-contract.md) together with the later approved decisions in [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5). In particular, [Vince’s provisional labeling decision](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428267359) and [Ayden’s approval](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428534359) settle the baseline settings listed below. This plan records those decisions without changing the API. Resolve any further disagreement in issue #5 before relying on it in an experiment.

The original draft was reviewed against `development` at `f4cd3ef`. As of November 2, [PR #6](https://github.com/aydsman/ML-DDoS-Detector/pull/6) (feature/dataset contracts), [PR #8](https://github.com/aydsman/ML-DDoS-Detector/pull/8) (normalization and epoch windows), [PR #10](https://github.com/aydsman/ML-DDoS-Detector/pull/10) (mock frontend/report outline), and [PR #7](https://github.com/aydsman/ML-DDoS-Detector/pull/7) (HTTP client, reviewed head `430a629`) are merged. This branch includes current development without rewriting Ali's history. Ayden independently ran all 113 tests at the client head and combined with development. Tests verify implemented helpers/client behavior; they do not establish live/offline adapter parity or a working end-to-end detector.

Capture adapters, training, inference, live API/firewall integration and experiment runners remain pending on this branch. Native Python tests and planning can run without a VM; live traffic/enforcement scenarios require the isolated Linux lab and the relevant components.

The companion [measurement specification](measurement-formats.md) defines metric denominators, collection methods, missing-data handling, and the [run-record template](templates/run-record.template.json). That record is an experiment artifact, not a new backend API response.

## Week 1 deliverables and completion

| Card requirement | Deliverable | Completion evidence |
| --- | --- | --- |
| Scenarios and acceptance checks for components and pipeline | Scenario tables below, with prerequisites and expected evidence | Component owners review their cases and resolve conflicting expectations |
| Detection, availability, latency, false-positive, resource, and capture-health metrics | Measurement specification | Every metric has a unit, population/denominator, collection source, and missing-data rule |
| Independent ground truth, run identifiers, and result formats | Run-record template and coordination table below | Mujtaba confirms the shared run ID and generator/client export fields; Vince and Ayden confirm time/window/event matching |

The documentation can be reviewed before the pipeline exists. Week 1 is not marked complete merely because a template parses or the existing tests pass: the result-format agreement remains pending until the relevant owners review it. Passing later lab cases is not required to finish the Week 1 planning card.

## Test records and outcomes

For each execution, record the case ID, tested Git commit, configuration, prerequisite checks, observed result, and evidence references using the measurement specification. Use these outcomes:

- `not_run`: no execution has been attempted.
- `blocked`: an explicit prerequisite, implementation, or agreed criterion is missing; name it.
- `passed`: the stated checks ran and their evidence satisfies the agreed expectations.
- `failed`: execution or observed behavior did not satisfy the stated checks; retain the evidence and reproduction details.

Missing data is not a pass, and an unavailable performance target does not permit a performance pass. Record measurements while keeping the affected acceptance decision blocked. A correctness check can still pass independently of an unresolved performance target.

## Local feature checks

These cases use in-memory packets and need no VM. Existing tests are in [test_features.py](../tests/test_features.py). The expanded checks below are specifications for follow-up tests, not additional tests implemented by this documentation change.

| ID | Inputs and prerequisite | Acceptance check | Evidence / current coverage |
| --- | --- | --- | --- |
| F01 | Empty supplied packet list; positive window duration | All 12 configured feature names exist and every value is zero. An empty input alone says nothing about capture health. | Existing test checks names only; exact zero-value assertions remain to be added. |
| F02 | Three IPv4/TCP packets, each 20-byte IP header + 20-byte TCP header + 20-byte payload, within one second | Each IP length is 60 bytes; byte rate is 180 bytes/s, mean is 60 bytes, population standard deviation is 0. Ethernet bytes are excluded. | Existing Scapy serialization/feature test; retain pytest output. This does not prove adapter parity. |
| F03 | Four normalized packets in two seconds: TCP SYN-only 60 bytes, TCP SYN+ACK 100 bytes, UDP 80 bytes, ICMP 80 bytes; two sources with two packets each | Packet rate 2 packets/s; byte rate 160 bytes/s; mean 80; population standard deviation `sqrt(200)` bytes; SYN count 1; SYN/ACK ratio 1; SYN-no-ACK share 0.5; two sources; entropy 1 bit; TCP/UDP/ICMP shares 0.5/0.25/0.25. | Proposed independent arithmetic fixture. Compare floating-point outputs with a documented tolerance; do not derive expected values by calling the extractor. |
| F04 | Nonzero sorted timestamps `10.9, 11.0, 11.5, 14.2`, one-second windows | Use the approved rule `start = floor(ts / window_seconds) * window_seconds`, with `[start, end)` bounds. Expected `(start, packet_count)` pairs: `(10,1), (11,2), (12,0), (13,0), (14,1)`. `11.0` belongs to the window starting at 11; a different first packet does not shift the epoch grid. | [PR #8 feature fixtures](https://github.com/aydsman/ML-DDoS-Detector/pull/8/files) cover epoch alignment, first-packet independence, boundaries, and gaps. The merged helper on this branch implements this epoch rule and its boundary/gap fixtures. Empty helper output alone does not prove healthy capture; adapter parity and end-of-capture evidence remain pending. |

Do not silently settle new behavior for negative durations, unsorted input, or malformed normalized records in a test. Agree input validation with Vince before specifying those cases as contractual behavior.

## Capture and dataset checks

| ID | Prerequisites | Acceptance check | Required evidence |
| --- | --- | --- | --- |
| C01 — packet normalization | Normalization fixtures first; both adapters for integration; use the approved None representation for unknown TCP flags | Select configured inbound IPv4 TCP/UDP/ICMP traffic to `10.10.10.10`. Use IP Total Length, excluding Ethernet. Non-first fragments contribute bytes/protocol but no invented TCP flags. Keep separate skip counts for `non_ip`, `ipv6`, `truncated_header`, `bad_length`, and `unsupported_protocol`; out-of-scope traffic has its own filter accounting. | [PR #8 normalization fixtures](https://github.com/aydsman/ML-DDoS-Detector/pull/8/files), specifically `tests/test_normalize.py`, cover IP size, fragments, truncated headers, protocol selection and skip reasons. Its `None` representation for unknown flags is approved and merged; fixtures do not demonstrate live/offline adapter parity. |
| C02 — offline/live parity and labels | Both adapters using epoch alignment and feature schema `"1"`; verified captures and ground truth | The same fixture produces the same ordered features and window IDs through both paths. Apply provisional attack-packet fraction `X = 0.80` only to eligible fully labelled, nonempty, nonboundary windows. Exclude unknown, mixed-below-threshold, boundary, and empty windows; require independent benign evidence for benign labels. | Both outputs, exact feature order, capture checksums, independent labels, exclusion counts and boundary examples. Report sensitivity to the provisional 80% threshold on validation data only; exact files, splits and label provenance still need verification. |

Use separate complete captures/runs for training, validation, and final testing. Verify the actual files and split membership; do not infer them from proposed dates or filenames. Tune neither model nor policy using final-test results.

## Lab and integration scenarios

All cases below are **planned and not executed by this work**. They require the isolated lab described in [lab-setup.md](lab-setup.md), independently recorded generator/client activity, and the named components. Traffic rates, duration, repetitions, performance targets, and recovery criteria must be agreed and recorded before execution; this plan does not supply traffic-generation commands.

Before each lab run, record a pre-run check with evidence:

- Verify the recovery snapshots and record their identifiers and owners.
- Verify NAT is disabled on the test VMs and the test network is isolated; confirm any management path with the lab owner.
- Reset and verify the starting firewall state, legitimate-client allowlist and cleanup/stop procedure.
- Confirm the protected target is **only `10.10.10.10`** inside the isolated lab.
- Verify the actual capture interface/filter and clock offsets/uncertainty; a documented interface name is not runtime evidence.

These are prerequisites for later execution, not claims that VM setup or lab checks have been performed here.

| ID / scenario | Prerequisites | Acceptance checks | Evidence to retain |
| --- | --- | --- | --- |
| L01 — legitimate steady traffic | Protected service and Mujtaba's repeatable HTTP client | Every attempted request has an outcome and elapsed time; counts reconcile. Record baseline availability and successful-response latency. Compare against agreed targets when available. | Client request records, service/configuration, run ID, actual start/end, clock checks. |
| L02 — legitimate burst | L01 plus capture and detector | Independently legitimate traffic is measured for false alerts; allowlisted legitimate clients receive no confirmed block. A burst is not labeled attack merely because a detector flags it. | Ground truth, prediction windows, confirmed firewall audit, request results. |
| L03 — controlled SYN scenario | Independent generator logs, verified capture, model; start in monitor-only | Selected traffic and window features reconcile with known input. Match aggregate predictions to independent labels; report precision/recall, false positives, misses, and delay. Monitor-only creates no automatic firewall requests. Performance targets remain pending until agreed. | Generator activity, capture/feature records, labels, predictions, client outcomes, capture health. |
| L04 — controlled UDP scenario | Same readiness as L03; protocol-specific configuration | Apply L03 checks to UDP without treating TCP-specific feature values as UDP evidence. Record actual sending activity rather than configured rate alone. | Same evidence as L03, with protocol and actual rate/counts recorded. |
| L05 — mixed legitimate and attack traffic | Ground-truth join and mixed-window policy agreed | Aggregate alerts do not identify a source by themselves. Only sources satisfying the separate attribution policy can be block candidates; the allowlisted legitimate client stays protected. Report excluded/unknown windows separately. | Independent source/activity evidence, aggregate IDs, attribution fields, requests and confirmed block events. |
| L06 — empty interval, capture failure, missing prediction | Capture diagnostics and event logging | A genuinely observed empty interval is distinguishable from a capture outage. Missing/failed intervals do not silently become benign or zero loss; they break the consecutive-qualification streak. Missing predictions remain visible in coverage and result accounting. | Health/counter records, window coverage, prediction gaps, policy state trace. |
| L07 — attribution and policy checks | Implemented policy; approved thresholds/share basis, allowlist and block cap | Use the controlled example below and variants for a nonqualifying interval, allowlisted source, full block cap, and missing configuration. Requests occur only when all required conditions hold; monitor-only requests none. | Fixed policy inputs, expected decisions, per-window rates/shares/streak, effective config, request log. |
| L08 — enforcement, expiry, and recovery | Implemented firewall adapter and isolated lab; recovery definition agreed | A request alone is never reported as an active block. Confirm apply/failure, expiration, removal and reconciliation. Failed enforcement remains visible. Measure legitimate-client availability and recovery with the agreed observation rule. | Firewall-confirmed timestamps/results, error and cleanup logs, client records before/during/after. |
| L09 — API/dashboard integration | Ayden's endpoints and Aadi's dashboard; mocks usable for early UI checks | Aggregate records have no invented source; source events refer to their aggregate event. Block lists contain confirmed active blocks. Empty/error/stale responses display honestly, and failed refreshes do not imply healthy traffic. | Contract checks, saved responses, UI evidence, timestamps and error cases. Mock-only results do not demonstrate live integration. |

### Controlled policy example for L07

The design specifies an acceptance example with three consecutive one-second windows: source `10.10.10.30` contributes 4,200 SYN packets/s and allowlisted `10.10.10.20` contributes 12 normal packets/s. Supply an attack decision for each window to test the policy independently of model quality. Under a configuration whose rate/share thresholds are exceeded and whose block cap has space, only the attack source becomes eligible after the third qualifying window. Monitor-only requests no block. Automatic mode may request only the eligible source after all checks.

This example specifies policy-test inputs, not measured traffic or tuned deployment thresholds. The approved share denominator is all selected inbound packets to the protected server, giving `4200 / (4200 + 12)`, approximately 99.7%, in this fixture. The provisional configurable lab cap is 20 active blocks; the actual allowlist and rate/share thresholds still require verified configuration. A missing/nonqualifying middle interval resets the streak. Never treat a copied aggregate attack score as confidence that a particular source is malicious.

## Experiment sequence for later weeks

1. Freeze the tested commit, model/preprocessing artifacts, feature order, label rules, service/client workload, VM resources, clock checks, and monitoring configuration. Store artifact hashes and the actual policy values.
2. Establish L01 baselines, then run the agreed relevant scenarios under `no_defense`, `monitor_only`, `rule_based`, and `ml_mitigation`. Define the rule-based comparator separately; it is not implemented by this plan.
3. Match workload, input captures or generator settings, duration, VM resources, and monitoring overhead across comparable runs. Record actual emitted activity and deviations. Use a documented ordering/repetition plan to reduce order effects; its count/order is still pending review.
4. Capture raw evidence first, join independent ground truth and predictions second, and calculate metrics last. Report exclusions, nondetections, missing observations, and failed runs alongside the headline values.
5. Retain per-run results and variability; do not pool observations from incompatible configurations or select only successful runs. Keep the final-test set separate from tuning.

## Decisions and owner review

The linked issue #5 decisions establish these planning baselines; they do not establish actual lab readiness or completed implementation:

| Decision | Recorded baseline / remaining check |
| --- | --- |
| Window and feature contract | Unix-epoch alignment, start-inclusive/end-exclusive windows, feature schema `"1"`. PRs #6/#8 are merged with the ordered input guard, shared normalizer and epoch-window tests; adapter parity and final interval handling still need evidence. |
| Labelling | Provisional attack-packet fraction `0.80`; preserve exclusions and report validation-only sensitivity. Exact captures, independent labels and split membership remain unverified. |
| Aggregate model threshold | `0.5` is an experimental baseline. Tune it using validation data only and keep final-test data untouched. It is distinct from the `0.80` label fraction and from source-attribution thresholds. |
| Source policy | Share uses all selected inbound server packets; three qualifying windows, 300-second TTL, initial monitor-only mode, and provisional configurable cap of 20 active blocks. Missing/quiet intervals break the streak. Verify the actual allowlist, rate/share thresholds and firewall behavior before use. |

The table distinguishes recorded planning agreements from evidence still needed for later collection. Ayden is completing these corrections on Ali's behalf; it does not claim Ali personally performed the client review. Final re-review of this PR remains pending.

| Owner | Confirmation needed | Current state / effect |
| --- | --- | --- |
| Mujtaba + Ali | Shared experiment/client ID mapping, success predicate, request outcomes/timeouts, complete exports, and independent generator activity | Mujtaba confirmed the W1 client mapping and initial status-only 2xx rule in his PR #9 comment. Ayden took over the review, verified PR #7 head 430a629 and accepted these conventions. The refreshed [mapping](measurement-formats.md#mapping-the-http-client-export) records that agreement; actual source/generator evidence and later experiment settings remain pending. |
| Vince + Ali | Actual capture interface/filter, counter semantics, clock bounds, snapshots/isolation evidence, interval coverage and adapter parity | Lab facts are separate from approved epoch alignment. Unknown flags use approved None and the twelve inbound feature formulas remain the version-one baseline. Actual adapter parity/coverage and validation of feature usefulness remain pending before trained/live compatibility claims. |
| Ayden + Vince + Ali | Verified dataset files/splits/labels, validation sensitivity and tuning, actual source thresholds/allowlist, artifact versions | Baselines above are accepted for planning; evidence and any changes require review. No final-test tuning. |
| Ayden + Ali | Positive/negative prediction logs, window/event identifiers and timing, missing prediction reporting | Pending; needed for reproducible evaluation joins. |
| Aadi + Ayden + Ali | Empty/error/stale UI cases, history limits, and accessible L09 evidence | Mock frontend and empty/error/stale cases were reviewed in merged PR #10. Live endpoints, retained evidence and L09 integration remain pending; follow the API contract. |
| All component owners + Ali | Workload rates/durations/repetitions, quantitative acceptance targets, resource sampler and recovery definition | Pending; performance pass/fail requires agreed targets and collection evidence. |

## Local validation and handoff

From the repository root with Python 3.12 and the local environment installed:

```sh
./.venv/bin/python -m pip check
./.venv/bin/python -m pytest -q
./.venv/bin/python -m json.tool docs/templates/run-record.template.json > /dev/null
```

These commands check dependency consistency, the implemented feature suite, and JSON syntax. They do not validate the proposed measurement semantics, live detection, or the firewall. Review the field definitions and confirm the owner decisions separately.

Keep real PCAPs, generator/client logs, and generated records in the ignored `data/`, `logs/`, or `results/` locations, with access/storage agreed by the team. Commit the plan and empty template, not measurements or captures. The template must be copied and populated for each real run; do not overwrite it with experiment results.

Submit this task branch as a PR into `development`. Move the task to review when the draft is available, retain unresolved decisions explicitly, and mark it done only after the Week 1 agreement checks are satisfied. Reviewed and tested changes can be promoted to `main` later through the team's workflow.

## November 2 review correction handoff

Ayden completed the requested document corrections on Ali's behalf: current client revision/counters, complete scheduled workload ledger, stable request identity, final CSV reconciliation, recorded component-side agreement and merged implementation status. See [Mujtaba's review](https://github.com/aydsman/ML-DDoS-Detector/pull/9#issuecomment-6478498003) and [PR #7](https://github.com/aydsman/ML-DDoS-Detector/pull/7) for the client review and merge. PR #9 still requires final peer review; later lab execution and quantitative targets are not fabricated as Week 1 results.
