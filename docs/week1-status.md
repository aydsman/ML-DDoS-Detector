# Ayden week-one handoff status

Checked October 27, 2026. Task: [Define interfaces and the ML feature contract](https://trello.com/c/INBpxEAL). Review: [PR #6 into development](https://github.com/aydsman/ML-DDoS-Detector/pull/6).

| Acceptance item | Evidence | Status |
| --- | --- | --- |
| Component input/output and prediction agreement | feature-contract.md, api-contract.md, api-examples.json | Prepared; PR review pending |
| Versioned ordered feature definitions/types/units | feature-contract.json and FEATURE_NAMES; numeric/version/name validation in contracts.feature_vector | Prepared and checked; capture/feature review still needed |
| Dataset subset and labeling approach | dataset-plan.md, bounded selection, label examples, manifest template | Plan prepared; real inventory/metadata evidence unavailable |
| Agreement with Vince | Approved five answers on issue #5; epoch alignment, aggregate capture, IP bytes, share denominator, provisional thresholds/cap recorded | Core decisions recorded; SYN/ACK/fragment and parity verification pending |
| Aadi handoff | aadi-handoff.md and Trello review request; Aadi says no API changes needed for his local mock | Recipient response received; files/layout not independently reviewed |

## What can be completed without waiting

The architecture, field documentation, ordered feature contract, input guard, dataset selection/label specification, acceptance cases, and handoff package are prepared on the PR branch. Input-guard tests check shuffled feature ordering and reject malformed data rather than silently scoring it. Existing feature tests remain in place. No model training, capture parity, frontend review, or lab run is implied.

## What prevents honest task closure

1. Vince must provide an actual capture manifest, trustworthy labels/timezone/splits, and sample feature records. The official download endpoint displayed an error during this check; no verified filenames/checksums can be claimed.
2. Vince/Ali must settle inbound-only SYN/ACK usefulness, unknown fragment flags, and verify offline/live extraction. These affect the shared training contract.
3. Review PR #6, and obtain Aadi's pushed mock/layout for the joint review. Aadi's self-reported local tests are evidence of progress, not independent verification.

Keep the card In progress, with these named dependencies. Do not mark Done or close issues #1-#3/#5 based on documentation alone. Training and full live enforcement belong to later tasks; the remaining gate is credible compatibility/evidence, not a requirement to finish the whole product in week one.
