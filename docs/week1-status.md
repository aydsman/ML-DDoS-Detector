# Ayden week-one planning closeout

Checked October 28, 2026. Task: [Define interfaces and the ML feature contract](https://trello.com/c/INBpxEAL).

The original Trello card asks for component inputs/outputs and API examples, a manageable dataset subset/labeling approach, and agreement on the shared features/window/units/missing-data rules. It does not require a trained model, complete live capture, finished firewall, or executed benchmark experiments. Earlier progress notes treated some of those later evidence checks as week-one closure gates; this record corrects that distinction without claiming they are finished.

| Original acceptance item | Delivered evidence | Planning status |
| --- | --- | --- |
| Component inputs, outputs and prediction/API examples | feature-contract.md; api-contract.md; api-examples.json; PR #6 reviewed by Vince and merged into development | Complete |
| Manageable subset and labeling approach supporting the chosen features | dataset-plan.md selects raw PCAP processing for SYN/UDP/benign, caps the pilot at 300 eligible windows per class/split, defines independent splits and exclusions, and separates model threshold from ground-truth labeling. Raw IP packet inputs support the specified packet/window features; normalization fixtures verify their byte/flag interpretation. | Selection and processing plan complete; actual file inventory/labels remain a prerequisite for training |
| Agreement on features/window/order/units/missing values | Twelve-feature version-one JSON/Markdown specification; ordered input guard; issue #5 decisions; approved/merged PR #8 with epoch alignment and None for unknown flags | Complete baseline specification; predictive usefulness and live behavior not certified |
| Handoff to Aadi | Aadi confirms all four sections use the fields; source/report/screenshots published; Ayden independently reviewed and approved PR #10; merged into development | Complete week-one mock review |

## Integrated verification

PR #6 supplies the architecture/specification and input validation. PR #8 supplies shared IPv4 normalization and epoch windowing; the review additionally fixed flag reads beyond declared IP length. PR #10 supplies the mock frontend and report outline. The integrated Python suite passes 46 tests. Independent browser checks covered representative, zero, empty, unavailable, stale, failed/recovered and initial-load-failure states plus narrow layout. These tests do not measure model quality or prove a live detector.

## Prerequisites carried forward, not claimed complete

- Vince/Ali: actual CIC capture inventory, hashes, timezone, trustworthy labels/splits and inspectable sample before model training. The October 27 official-download check failed; manifest example fields remain null. The bounded plan must be revised if usable independent captures cannot be obtained. Do not train or claim benchmark results using this template.
- Vince/Ali: real offline/live adapters and capture-coverage/parity evidence; runtime interface/allowlist confirmation; late/out-of-order handling.
- Ayden/Vince: source rate/minimum-share tuning and model threshold selection using validation data only. Keep monitor-only operation until policy prerequisites are met. Evaluate inbound SYN feature redundancy; any definition change requires a new schema.
- Ayden/Aadi: finalized pagination/cursors, error payloads, per-endpoint freshness and partial failure handling before live API integration. Current 60 chart points / 50 rows per page / 5-second stale warning are provisional defaults, not implemented API behavior.

These remain tracked in [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5) and the original issues #1-#3. Do not close those evidence issues as part of week-one planning closeout. In particular, Ayden's Week 2 training task must not bypass the dataset gate.

The week-one card can be marked Done for its planning deliverables once this closeout is merged. Done describes the completed architecture/handoff task, not the finished project or verified training data.
