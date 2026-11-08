# Week-one dataset selection and label specification

Owner: Ayden; capture inventory/normalization: Vince; independent label review: Ali. This is a bounded selection plan, not a verified downloaded dataset. It complements [design](design.md) and [the feature contract](feature-contract.md).

## Verified source and access status

Checked October 27, 2026: the [official CIC-DDoS2019 page](https://www.unb.ca/cic/datasets/ddos-2019.html) describes raw PCAPs, labeled flow CSVs, and SYN/UDP scenarios across training/testing collections. It recommends raw captures for a custom extractor. Its first/second-day table and prose are insufficient to assign exact calendar dates and timezone safely; match the downloaded metadata before converting times. Flow CSV rows are not this project's one-second aggregate features.

The earlier automated retrieval error did not establish that the download service was unavailable: the interactive registration page loaded on October 29. Vince subsequently reported accessing the [official download page](https://cicresearch.ca/CICDataset/CICDDoS2019/) and downloading the two CSV archives. His [issue #3 inventory](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6502234272) supplies names, byte sizes and locally calculated SHA-256 values; these are collaborator-reported evidence, not independently verified files or publisher checksums. Vince subsequently [reported all five PCAP archives downloaded and extracted on November 3](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6617753926). See the updated [reported inventory](dataset-inventory-reported.json). Archive/member contents, hashes, packet labels and split independence have not been independently verified by Ali.

### October 30 selection decisions and next evidence

- Keep SYN, UDP flood and independently verified benign traffic only. Exclude MSSQL rows in the reported `03-11/UDP.csv`; also exclude their associated packets/windows from any future PCAP selection. Dropping a CSV row does not remove packets from a capture. Other out-of-scope traffic must likewise be excluded or cause a window to be excluded, never relabelled benign.
- BENIGN rows are mixed into the reported CSV files. A separate benign file is not required, but a BENIGN flow label alone does not establish that a complete aggregate packet window is benign. Verify every selected packet's labels and coverage using the existing label rules.
- Provisionally nominate `01-12` for training/validation and `03-11` for the untouched final test. These are folder identifiers, not verified calendar dates. Do not activate the split until timestamps, timezone, schedule mapping and independent capture/run IDs are verified. Archive chunks alone do not establish independent runs. If separate validation runs are unavailable, return to Ayden/Ali with a revised split proposal before training.
- Retain the packet-based twelve-feature contract. Flow CSV features are not equivalent model inputs. Any CSV-to-PCAP label mapping needs a reproducible method, documented ambiguous/unmatched cases and Ali's independent sample review; do not guess packet labels from source IP or time alone.
- Raw data stays outside Git and preferably outside synced project folders. Vince's reported location is `C:\Users\iamno\datasets\cic-ddos2019\`; each member can use a different local root. Commit manifests and small reviewed samples, not archives or full generated datasets. The example manifest remains a template until real selection evidence is available.
- Before selecting a PCAP download, Vince should provide exact archive/member URLs and names, relevant capture timestamps/time ranges, compressed/unpacked sizes (or explicitly unknown estimates), available disk space, victim/filter evidence and proposed split/run IDs. Check whether a bounded subset can be obtained without downloading all archives. No PCAP download or split is claimed by this decision.
- Next handoff: Vince provides the inventory/metadata and a small candidate selection; Ayden reviews scope and split, and Ali independently checks labels and exclusions. Training waits for those checks and adapter parity.

## November 6 candidate handoff

PR #27's inspection utility is merged. [PR #29](https://github.com/aydsman/ML-DDoS-Detector/pull/29) supplies a SYN candidate join and 479 enriched records, with member/CSV hashes reported in its manifest. Ali independently reconciled 8 candidate attack and 471 excluded windows, and reproduced boundary/provenance defects in the join. See [the exact-head review and repeatable probes](reviews/issue-3-pr29-review.md). Raw file hashes and the empirical four-hour offset have not been independently reproduced here. No benign windows, independent runs or reviewed split are supplied. Keep the manifest unreviewed and issue #3 open; this is progress on the handoff, not approval for training.

## November 4 independent-review status

The [latest bounded handoff](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6621822689) uses Vince's existing files; no additional bulk download is needed. Start with reported SYN candidate suffixes 0618–0620 and a small named training-side UDP selection. Supply exact member names/hashes, inspection scripts and reproducible packet/flow/window evidence before Ali's independent review. Do not adopt the packet scan's apparent victim/source identities or an inferred four-hour schedule shift as ground truth.

The official description confirms raw PCAPs and labelled flow CSVs, but the readable schedule does not establish calendar dates or timezone. The November 4 read-only download-page retrieval returned a registration form/server error, so it did not verify direct archive links or publisher sizes/hashes. Vince's report remains useful collaborator evidence; this retrieval result does not invalidate his downloads.

DrDoS_UDP and UDP may be different reflection/flood scenarios; keep that distinction explicit in a proposed cross-scenario evaluation. Neither file names nor archive pieces establish independent train/validation/test runs. See [Ali's evidence review and handoff checks](dataset-review.md) for current checks and the required real sample. The enriched training format is in [training.md](training.md#real-data-handoff-format). Issue #3 remains open; the new label-contract tests check synthetic logic only.

## Concrete first subset

Select only SYN, UDP flood, and independently verified benign traffic. Exclude UDP-Lag, DNS, NTP, other attack types, uncertain labels, and unsupported traffic. Pilot target: at most 300 eligible one-second windows per class per split (train, validation, final test), at most 2,700 total windows. This is a manageable feature-table target, not a claim about PCAP size, guaranteed class balance, or statistical adequacy.

Assign whole independent capture/run IDs to splits before selecting windows. Training/validation must come from separate verified runs/captures in the training collection; final test from the verified testing collection. No random neighboring-window split. If independent benign/SYN/UDP runs cannot support this plan, record the shortage and revise the design with Ayden/Ali rather than slicing one run and claiming independent evaluation. Keep class counts/exclusion counts visible even if the final subset is smaller. Never tune using final-test windows.

For each split/class selection, enter into a manifest: source URL, original filename, byte size, SHA-256, capture/run ID, split, victim address, verified interval bounds in UTC epoch seconds, original timezone and evidence, class, label metadata reference, selected windows, and exclusion reasons. Fields remain unfilled until Vince inspects actual files; [manifest template](dataset-manifest.example.json) uses null explicitly for unavailable evidence. Store raw captures outside the repository (an explicitly gitignored local data/ directory is also possible), measure compressed/unpacked needs, and do not begin a large download without checking available disk space.

## Label decision order

Apply to complete, epoch-aligned aggregate inbound-to-victim windows, with independently derived packet labels. Split assignments and label metadata are separate from ML input features.

1. Exclude unavailable capture coverage, malformed metadata, unknown packet labels, and schedule/label boundary windows. Do not turn unknown into benign.
2. Exclude measured empty windows. They remain useful for chart/coverage diagnostics and break source streaks.
3. For a nonempty, fully labelled, nonboundary window, attack fraction is attack-labelled selected packets / all selected packets. Label attack when fraction >= 0.80. This provisional labeling setting is separate from the 0.5 model-score baseline.
4. If fraction is zero, outside every verified attack interval, and all selected packets are independently benign, label benign.
5. Otherwise exclude: mixed below 80%, or inside an attack interval without confirmed attack packets. Record the specific reason.

A source address and schedule overlap alone are not reliable packet labels for spoofed traffic. If identity evidence is insufficient, retain unknown labels and exclude those windows. Report excluded counts and coverage alongside headline metrics; sensitivity to the provisional 80% rule uses validation data only.

## Acceptance examples (illustrative, not dataset measurements)

| Fully measured 1-second window | Expected label/reason |
| --- | --- |
| 8 independently attack-labelled + 2 independently benign packets; no boundary/unknown | attack (80%) |
| 7 attack + 3 benign; no boundary/unknown | excluded_mixed (70%) |
| 10 independently benign, outside all attack intervals | benign |
| 10 benign-labelled but inside attack interval | excluded_interval_without_attack |
| Any unknown labels, even with 8 attack-labelled packets | excluded_unknown |
| Any schedule boundary overlap | excluded_boundary |
| Zero packets with confirmed coverage | excluded_empty |
| No reliable capture coverage | excluded_unavailable, never fabricated zero |

These specify expected logic for Ali's independent review. They do not certify the metadata, produce final public-data labels, or replace offline/live parity evidence.

## Go/no-go for training

Train only after the real manifest and label sample are reviewed, the inbound SYN/ACK and fragment policy is resolved, and adapters demonstrate the agreed feature definitions. If CIC access/ground truth remains unusable, propose a lab-only pilot with independently logged runs as an explicit scope change; do not silently replace the public-data experiment or manufacture benchmark results. Issue [#5](https://github.com/aydsman/ML-DDoS-Detector/issues/5) remains the evidence tracker.
