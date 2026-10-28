# Week-one dataset selection and label specification

Owner: Ayden; capture inventory/normalization: Vince; independent label review: Ali. This is a bounded selection plan, not a verified downloaded dataset. It complements [design](design.md) and [the feature contract](feature-contract.md).

## Verified source and access status

Checked October 27, 2026: the [official CIC-DDoS2019 page](https://www.unb.ca/cic/datasets/ddos-2019.html) describes raw PCAPs, labeled flow CSVs, and SYN/UDP scenarios across training/testing collections. It recommends raw captures for a custom extractor. Its first/second-day table and prose are insufficient to assign exact calendar dates and timezone safely; match the downloaded metadata before converting times. Flow CSV rows are not this project's one-second aggregate features.

The [official download link](https://cicresearch.ca//CICDataset/CICDDoS2019/) returned a registration form with "Server error. Please try again later." Exact file inventory, byte sizes, checksums, and actual PCAP metadata could not be verified. No form was submitted or captures downloaded. Do not substitute guessed filenames or a third-party processed CSV as equivalent evidence.

## Concrete first subset

Select only SYN, UDP flood, and independently verified benign traffic. Exclude UDP-Lag, DNS, NTP, other attack types, uncertain labels, and unsupported traffic. Pilot target: at most 300 eligible one-second windows per class per split (train, validation, final test), at most 2,700 total windows. This is a manageable feature-table target, not a claim about PCAP size, guaranteed class balance, or statistical adequacy.

Assign whole independent capture/run IDs to splits before selecting windows. Training/validation must come from separate verified runs/captures in the training collection; final test from the verified testing collection. No random neighboring-window split. If independent benign/SYN/UDP runs cannot support this plan, record the shortage and revise the design with Ayden/Ali rather than slicing one run and claiming independent evaluation. Keep class counts/exclusion counts visible even if the final subset is smaller. Never tune using final-test windows.

For each split/class selection, enter into a manifest: source URL, original filename, byte size, SHA-256, capture/run ID, split, victim address, verified interval bounds in UTC epoch seconds, original timezone and evidence, class, label metadata reference, selected windows, and exclusion reasons. Fields remain unfilled until Vince inspects actual files; [manifest template](dataset-manifest.example.json) uses null explicitly for unavailable evidence. Store captures in gitignored data/, measure compressed/unpacked needs, and do not begin a large download without checking available disk space.

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
