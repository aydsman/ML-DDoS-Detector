# Test plan and acceptance checks

Owner: Ali (QA and Performance Engineer). Status: **draft for Week 1 review**.

Task: [W1 — Define the test plan and measurement formats](https://trello.com/c/dSv2o6Fu), planning deadline October 28, 2026, 5 p.m. America/Toronto.

This plan defines what to check and what evidence to keep. It is not an experiment report. A listed scenario is not evidence that it has run or passed.

## Scope and source of requirements

Use the [design](design.md) for feature, labeling, and mitigation behavior and the [API contract](api-contract.md) for API fields. This plan does not change either contract. Record disagreements and unresolved decisions in [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5) before relying on them in an experiment.

The current repository contains feature extraction, window grouping, and four feature tests. Capture adapters, training, inference, the API, firewall integration, and experiment runners are still pending. Native Python tests and this planning work can be completed on a Mac; live traffic and enforcement scenarios require the isolated Linux lab and the relevant components.

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
| F04 | Sorted timestamps `0.0, 0.999, 1.0, 2.001`, one-second windows; separate gap fixture `0.0, 3.0` | First fixture groups as 2/1/1; a timestamp at the end belongs to the next window. Gap fixture exposes the two empty intervals. Record that the current helper anchors to the first packet. | Existing split test is partial coverage. Boundary/gap assertions remain to be added. Shared offline/live origin and end-of-capture handling still need agreement. |

Do not silently settle new behavior for negative durations, unsorted input, or malformed normalized records in a test. Agree input validation with Vince before specifying those cases as contractual behavior.

## Capture and dataset checks

| ID | Prerequisites | Acceptance check | Required evidence |
| --- | --- | --- | --- |
| C01 — packet normalization | Vince's adapters and agreed fragment/truncation rules | Select only configured inbound IPv4 TCP/UDP/ICMP traffic to the protected destination. Normalize IP lengths consistently; malformed, non-IP, and out-of-scope packets have explicit skip outcomes. A missing source/header field is not invented. | Inspectable packet fixtures; independently calculated accept/skip/size expectations; skip diagnostics with documented meaning. |
| C02 — offline/live parity and labels | Both adapters, shared window origin/order, verified captures and ground truth | The same fixture produces the same ordered features and window IDs through both paths. Independently verified labels retain provenance. Unknown/mixed/boundary/empty cases follow the agreed exclusions. | Both outputs, configuration, capture checksums, label evidence, boundary examples, and comparison results. Pending label fraction X is not assumed to be 80%. |

Use separate complete captures/runs for training, validation, and final testing. Verify the actual files and split membership; do not infer them from proposed dates or filenames. Tune neither model nor policy using final-test results.

## Lab and integration scenarios

All cases below are **planned and not executed by this work**. They require the isolated lab described in [lab-setup.md](lab-setup.md), independently recorded generator/client activity, and the named components. Traffic rates, duration, repetitions, performance targets, and recovery criteria must be agreed and recorded before execution; this plan does not supply traffic-generation commands.

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

This example specifies policy-test inputs, not measured traffic or tuned deployment thresholds. Use the agreed share denominator; the approximately 99.7% example assumes all selected packets. A missing/nonqualifying middle interval resets the streak. Never treat a copied aggregate attack score as confidence that a particular source is malicious.

## Experiment sequence for later weeks

1. Freeze the tested commit, model/preprocessing artifacts, feature order, label rules, service/client workload, VM resources, clock checks, and monitoring configuration. Store artifact hashes and the actual policy values.
2. Establish L01 baselines, then run the agreed relevant scenarios under `no_defense`, `monitor_only`, `rule_based`, and `ml_mitigation`. Define the rule-based comparator separately; it is not implemented by this plan.
3. Match workload, input captures or generator settings, duration, VM resources, and monitoring overhead across comparable runs. Record actual emitted activity and deviations. Use a documented ordering/repetition plan to reduce order effects; its count/order is still pending review.
4. Capture raw evidence first, join independent ground truth and predictions second, and calculate metrics last. Report exclusions, nondetections, missing observations, and failed runs alongside the headline values.
5. Retain per-run results and variability; do not pool observations from incompatible configurations or select only successful runs. Keep the final-test set separate from tuning.

## Decisions and owner review

These are requests for review, not approvals already received. Record the reviewing person and a linked PR comment or issue decision when resolved.

| Owner | Confirmation needed | Current state / effect |
| --- | --- | --- |
| Mujtaba + Ali | Run ID propagation; request attempts/outcomes/timeouts; independent generator intervals and actual activity; export fields and units | Pending. Shared record format cannot be called agreed yet. |
| Vince + Ali | Capture interface and filters; counter semantics; clock offsets/uncertainty; window origin/order/end behavior; normalized fixtures and adapter parity | Pending in issue #5. Real capture coverage and delay claims require this evidence. |
| Ayden + Vince + Ali | Model threshold versus source thresholds; share denominator/cap/allowlist; exact dataset files, split and independent label rules including X | Pending in issue #5. No arbitrary defaults or final-test tuning. |
| Ayden + Ali | Prediction/window identifiers and event timing; model/version metadata; missing prediction reporting | Pending. Needed for reproducible evaluation joins. |
| Aadi + Ayden + Ali | Empty/error/stale UI cases, history limits, and accessible evidence for L09 | Pending. Follow the API contract rather than adding dashboard fields to suit a metric. |
| All component owners + Ali | Workload rates/durations/repetitions; success-status policy; quantitative acceptance targets; resource sampler and recovery definition | Pending. Proposed metric definitions can be reviewed now; performance pass/fail requires agreed targets. |

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
