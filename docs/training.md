# Week 2: baseline ML pipeline

Owner: Ayden. Status: code prepared for review; verified-data training/evaluation is pending. No public dataset accuracy, trained deployment model or completed W2 milestone is claimed by the synthetic demo.

## What the code does

`ddos_detector.training_data` prepares enriched, labelled packet windows using the existing twelve-feature contract. It rejects incompatible fields/order, invalid numbers, unknown provenance, duplicate windows, shared captures/content across splits and incorrect epoch boundaries. It keeps independently assigned train/validation/test runs; it never randomly splits adjacent windows.

The loader checks the supplied label against packet counts and exclusion rules. Unavailable, capped, unknown, boundary, empty, mixed-below-80% and inside-interval-without-attack windows must be labelled `excluded`; they are counted by reason and never imputed. Each split needs eligible benign and attack examples. The binary model combines supported SYN/UDP attacks into `attack`; this is not an attack-type classifier.

`ddos_detector.training` fits a Random Forest on training rows only. Defaults: 100 trees, seed 3670, one worker, balanced class weights computed by the estimator from training labels, threshold 0.5. No scaling or imputation is used; that choice is saved explicitly. Settings are provisional, not validated optimums. Only validation predictions/metrics are produced during training. Final-test scoring requires a separate command after settings are frozen.

The package saves `model.joblib`, `metadata.json` and `validation.json`. Metadata records the feature contract/order, packet scope/size, window, preprocessing, settings, threshold, dependency versions, input/manifest checksums, provenance counts and model checksum. Loading rejects incompatible metadata, different dependency versions and changed model bytes. A checksum detects accidental changes; it does not authenticate an untrusted package. Load only models generated locally or obtained through the team's trusted review process: joblib uses pickle and can execute code on load. See the [scikit-learn persistence guidance](https://scikit-learn.org/stable/model_persistence.html).

Training verifies identical probabilities after save/reload. Scores describe an aggregate window, never source-level confidence. The score is the forest's class probability output and is not claimed to be calibrated.

## Start now: explicitly synthetic software check

From the repository root in PowerShell, with Python 3.12 and project dependencies installed:

```powershell
.\.venv\Scripts\python.exe -m tools.create_training_demo results/w2-demo-input
.\.venv\Scripts\python.exe -m ddos_detector.training prepare --records results/w2-demo-input/records.json --manifest results/w2-demo-input/manifest.json --allow-synthetic
.\.venv\Scripts\python.exe -m ddos_detector.training train --records results/w2-demo-input/records.json --manifest results/w2-demo-input/manifest.json --allow-synthetic --output results/w2-demo-model
.\.venv\Scripts\python.exe -m ddos_detector.training score --model results/w2-demo-model --record results/w2-demo-input/score-record.json
```

Use new output directories for each run; existing artifacts are never overwritten. The `synthetic-code-check` status and `data_kind: synthetic` travel with the model/results. The artificial patterns are intentionally simple: any resulting metrics check software plumbing only and cannot establish accuracy, generalization or real-world detection. Nothing from `results/` belongs in Git.

Linux uses `./.venv/bin/python` in place of the Windows interpreter. No VM, packet capture or network traffic is needed for this demo. Run tests with `python -m pytest -q` using the same environment.

## Real-data handoff format

Supply a JSON array of enriched windows and a separate JSON manifest. The manifest is an explicit split assignment and review record, not the original CIC flow CSV. Raw captures stay outside Git. Vince's proposed PR #18 exports flat feature records without labels/run provenance; a reviewed join into this format is still required. Do not infer labels from extractor output or rename its CSV as a training dataset.

Manifest fields:

| Field | Required content |
| --- | --- |
| `data_kind` | `reviewed_packet_windows` for real reviewed input; `synthetic` only for fixtures |
| `feature_schema_version`, `feature_names` | `"1"` and the exact ordered `FEATURE_NAMES` list |
| `window_seconds`, `window_alignment` | `1.0`, `unix_epoch` |
| `scope`, `size_definition` | `protected_server_inbound_ipv4_tcp_udp_icmp`, `ipv4_total_length_bytes` |
| `review_refs` | Nonempty `labels`, `splits`, `feature_parity` references to actual review/evidence |
| `runs` | Object keyed by independent run ID; each value has `split` (`train`, `validation`, `test`) and `capture_ids` |
| `captures` | Object keyed by capture ID; each value has actual `sha256` and `label_metadata_reference` |

Review references and recorded checksums are attestations to supplied evidence, not proof manufactured by the loader. The loader does not have to load raw PCAPs and cannot independently verify their content or truth. Reviewers must confirm hashes, independent run identities, packet labels, timezone/victim filters and coverage before approving this manifest. Do not mark synthetic, guessed, overlapping-run or unreviewed data as reviewed. Renamed archive chunks are not independent runs.

Every window record has:

| Field | Meaning |
| --- | --- |
| `window_id`, `run_id`, `capture_id` | Unique window identity and references into the manifest |
| `window_start`, `window_end` | Epoch seconds, one-second half-open interval on the epoch grid |
| `features` | Object containing exactly the twelve contract features; may be null for excluded windows |
| `packet_count`, `attack_labelled_packets`, `unknown_packets` | Nonnegative integers from independently reviewed packet/label evidence |
| `capture_state` | `valid`, `failed`, `missing` or `uncertain` |
| `capped`, `boundary`, `inside_attack_interval` | Explicit booleans; capped source counts are excluded rather than certified as exact |
| `label` | `benign`, `attack` or `excluded`, consistent with evidence/exclusion rules |
| `label_reason` | Nonempty reason tied to the capture's label metadata; retain more detailed provenance in source artifacts |

All selected packets not counted as attack or unknown must have independently verified benign labels. The code cannot establish this just from subtraction. Use the same packet filter/feature semantics as live capture. The bounded 300 eligible windows per class/split selection plan remains a data-selection responsibility before loading; this code does not silently subsample or claim class balance. Summaries retain actual counts and exclusions. See [dataset-plan.md](dataset-plan.md) and issues #2/#3/#5.

Once data is verified, omit `--allow-synthetic` and use reviewed input paths. Run `prepare`, inspect counts/exclusions and provenance with Ali, then train. Choose tree settings/threshold on validation data only, using a new output per candidate; record the selection rationale. Do not repeatedly inspect the final test while selecting settings.

## Initial evaluation and final test

Validation output includes per-window scores, confusion counts/matrix (rows actual benign/attack, columns predicted benign/attack), accuracy, precision, recall, F1 and false-positive rate, with sample/class counts and exclusions. Null ratios have zero denominators; no perfect value is invented. This is eligible-window evaluation, not a measurement of capture loss, pipeline coverage or latency.

When settings/data are frozen and reviewed, explicitly run:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.training final-test --records data/reviewed-windows.json --manifest data/reviewed-splits.json --model results/baseline-v1 --output results/baseline-v1/final-test.json
```

The input and manifest checksums must match the frozen training package, and an existing final-test report cannot be overwritten. The CLI cannot prevent an operator from copying artifacts or choosing another filename, so the team must enforce the single final evaluation/no-test-tuning policy. The synthetic demo may exercise this command with `--allow-synthetic`, but its results remain software checks.

For scoring one saved feature record, provide a JSON object with `features`, `feature_schema_version: "1"`, `window_seconds: 1.0`, `capture_state: "valid"` and `capped: false`. Empty/unavailable/capped windows are rejected. The calling capture adapter is responsible for supplying the agreed inbound IPv4 scope, truthful coverage and features; this scorer does not implement that adapter or an API.

## What remains before W2 is Done

- Vince/Ayden: select actual usable PCAP subset and metadata; agree independently separated runs and make the labelled-window join reproducible.
- Vince: verify extraction/coverage and offline/live feature compatibility (PR #18 is still separate work, not automatically approved by this pipeline).
- Ali or the delegated reviewer: independently inspect label/exclusion sample and split evidence.
- Ayden: prepare the real table, train baseline, choose settings/threshold from validation, save/reload and record actual evaluation/provenance/limitations.
- Peer review and passing CI, then merge this task into `development`. Weekly promotion into `main` is a separate reviewed milestone.

The new code and synthetic run are the work possible before those data dependencies arrive. Final test belongs after settings are frozen; final model comparison and report conclusions remain later milestones.
