# Ayden's report contribution: machine-learning method

Author: Ayden Sendrea. Prepared November 3, 2026 for Aadi's report assembly.

**Status and evidence boundary.** This contribution describes the agreed method and the offline implementation prepared in [PR #19](https://github.com/aydsman/ML-DDoS-Detector/pull/19), inspected at commit `07f1d1af62821afe569e319cacea3da6b249d37c`. That code is under review and is not yet merged into development. Verified public-data training, a deployment model and real-data performance results are pending. The method below must not be presented as a completed experiment. Aadi can adapt the prose for report sections 3, 5, 6, 9 and 11; the final results table must be completed from retained experiment evidence.

## Detection architecture and model responsibility

The proposed detector classifies one aggregate window of inbound traffic to the protected server. A window contains selected IPv4 TCP, UDP and ICMP packets, rather than traffic grouped by individual source. The model produces a binary attack score for the combined window. This design preserves aggregate source-diversity information while keeping model prediction separate from source attribution.

A subsequent deterministic policy examines source/protocol counts when the aggregate model flags a window. It decides whether a particular source satisfies the configured rate, traffic-share, consecutive-window and allowlist conditions. The aggregate score is not a probability that a particular IP is malicious. Likewise, a predicted attack is not proof that a firewall block was applied. Backend integration, attribution and firewall confirmation remain separate components and later implementation work.

## Packet windows and the twelve input features

The version-one input uses one-second, non-overlapping windows aligned to Unix epoch time. Each interval includes its start and excludes its end. Selected traffic is inbound to a verified protected destination on the monitored interface. Dataset victim addresses must come from dataset evidence; the lab address is not assumed to apply to public captures.

Packet size means IPv4 Total Length: IP headers, transport headers and payload are included, while Ethernet headers are excluded. Packet timestamps, source addresses, run identifiers and ground-truth labels are retained as provenance, not supplied as model inputs. The exact feature order is fixed:

| Position | Feature | Interpretation |
| --- | --- | --- |
| 1 | `packet_rate` | Selected packet count divided by window duration, packets/s |
| 2 | `byte_rate` | Sum of selected IPv4 lengths divided by duration, bytes/s |
| 3 | `syn_count` | TCP packets with SYN set and ACK unset |
| 4 | `syn_ack_ratio` | SYN-only count divided by max(SYN+ACK count, 1) |
| 5 | `syn_no_ack_share` | SYN-only count divided by max(SYN-only count + ACK-set count, 1) |
| 6 | `pkt_size_mean` | Mean IPv4 packet length, bytes |
| 7 | `pkt_size_std` | Population standard deviation of IPv4 packet lengths, bytes |
| 8 | `unique_src_ips` | Number of distinct selected source addresses |
| 9 | `src_ip_entropy` | Base-two Shannon entropy of source packet-count proportions, bits |
| 10 | `tcp_share` | TCP count divided by all selected packet count |
| 11 | `udp_share` | UDP count divided by all selected packet count |
| 12 | `icmp_share` | ICMP count divided by all selected packet count |

The input guard rejects missing/extra features, invalid ordering/version metadata, non-finite or negative values, out-of-range fractions and non-integral count values. Model vectors use the declared order and float64 values. Unknown transport flags are distinct from observed zero flags; usable fragments can contribute aggregate packet/byte counts without invented TCP flag evidence. Inbound SYN/ACK ratios do not establish successful bidirectional handshakes. Their usefulness must be examined on validation data before changing the feature schema.

A confirmed empty window is distinguishable from capture failure. Empty windows are excluded from training and inference; unavailable coverage must never be replaced by a synthetic zero vector. These conventions are specified in [the feature contract](../feature-contract.md) and [the design](../design.md).

## Dataset selection, labels and leakage prevention

The planned initial scope is CIC-DDoS2019 SYN, UDP and independently verified benign traffic. Exact PCAP members, hashes, victim filters, timestamps/timezones and independent run identities still require verification. Flow-level CSV features cannot be substituted for the twelve packet-window features. Any join from label metadata to captured packets must be reproducible and independently reviewed.

The provisional packet-based label rule first excludes windows with unavailable coverage, capped counts, unknown labels, label/schedule boundaries or no packets. For a fully observed, nonboundary window, the attack fraction is independently attack-labelled selected packets divided by all selected packets. Fractions of at least 80% qualify as attack. A benign label requires all packets to be independently benign and the window to lie outside verified attack intervals. Other mixed or uncertain cases are excluded with explicit reasons. The 80% ground-truth rule is separate from the model's decision threshold; neither is an observed detection result.

Whole independent capture/run groups are assigned to training, validation and final test before selecting windows. Adjacent windows from one run are not randomly distributed across those splits. Duplicate windows, shared run/capture identities and reused capture hashes are rejected by the prepared loader. Human review must still establish that supplied identities, coverage and labels are truthful. Merely renaming archive chunks or adding a review-reference field does not establish independence.

The folder identifiers `01-12` and `03-11` are provisional collection choices, not verified dates or an approved split. DrDoS_UDP and UDP may represent different scenarios; any cross-scenario evaluation must be identified explicitly. The pilot target is at most 300 eligible windows per class per split, up to 2,700 windows overall. This is a bounded selection target, not a claim that sufficient independent runs or balanced classes have been obtained. The final test remains untouched while selecting features, settings and thresholds. This separation follows the general evaluation principle of reserving unseen data for final assessment. [Scikit-learn evaluation guidance](https://scikit-learn.org/stable/modules/cross_validation.html)

## Baseline classifier and reproducible training

The prepared baseline uses scikit-learn's RandomForestClassifier. A forest combines multiple decision trees; scikit-learn's classifier averages their class-probability estimates. It is a reasonable initial candidate for the tabular packet-window features, but its suitability and performance must be demonstrated on the project's reviewed data. No superiority over other methods is claimed. [Scikit-learn ensemble guidance](https://scikit-learn.org/stable/modules/ensemble.html#forest)

The explicit defaults in PR #19 are 100 trees, random seed 3670, one worker and balanced class weights derived from the training labels. The baseline performs no scaling or imputation. Only training rows are used to fit the estimator; validation rows are used for initial predictions and evaluation. Other estimator settings retain the defaults of the recorded scikit-learn version. These are starting settings, not a validated optimum.

The attack score is the forest's probability output for the aggregate attack class. A provisional threshold of 0.5 classifies scores greater than or equal to the threshold as attack. The binary target combines supported SYN/UDP attacks into one attack class; the model is not an attack-type classifier. Scores are not claimed to be calibrated confidence estimates. Final settings and threshold selection will use validation evidence, considering missed attacks and false alarms, and will be recorded before final-test evaluation.

## Saved artifacts and compatibility

The implementation saves `model.joblib`, `metadata.json` and `validation.json` into a new output directory. Metadata records ordered features, schema, numeric type, packet/window definitions, preprocessing, settings/seed/threshold, dependency versions, code revision, input/manifest hashes, provenance summaries and the model checksum. A save/reload check compares validation probabilities exactly within the recorded environment.

The loader checks compatible feature metadata, unchanged model bytes, matching Python major/minor and exact recorded NumPy, scikit-learn, SciPy and joblib versions. Python patch versions are retained in provenance; permitting patch differences does not prove cross-machine compatibility. Target-VM verification is still required. Only trusted model packages should be loaded: joblib persistence uses pickle mechanisms that can execute code, and a checksum alone does not authenticate a package. [Scikit-learn persistence guidance](https://scikit-learn.org/stable/model_persistence.html)

## Evaluation method and results still to collect

Validation records contain window identities, labels and scores, actual class/sample counts, exclusion counts and a confusion matrix with actual classes as rows and predicted classes as columns. The implemented metrics are accuracy, attack precision, attack recall, F1 and benign false-positive rate. Ratios with a zero denominator are recorded as null rather than assigned a perfect value. Capture coverage and excluded-window counts must accompany eligible-window metrics; a high score on a narrowly retained subset does not establish performance on all observed traffic.

Final-test evaluation uses a separate command with the frozen input/manifest hashes and model settings. The code prevents overwriting an existing output report, while the team must enforce the policy against repeated test-driven tuning. Detection delay, service availability, legitimate-client recovery, resource overhead and confirmed mitigation outcomes require later integrated experiments with Ali, Mujtaba and Vince. They cannot be inferred from offline classification metrics.

| Evidence item | Current status / required report entry |
| --- | --- |
| Data manifest, selected files and checksums | Pending verified inventory and label mapping |
| Independent split/run assignments | Pending review by Ayden and Ali with Vince's evidence |
| Eligible class counts and exclusions by split | Pending real-data preparation |
| Final settings and threshold rationale | Pending validation-only selection |
| Validation confusion matrix, precision, recall, F1 and false-positive rate | Pending real-data training; do not substitute synthetic metrics |
| Frozen model hash and saved-artifact location | Pending accepted real-data model |
| Untouched final-test results | Pending frozen settings and final evaluation |
| Detection latency and mitigation/service outcomes | Later integrated experiments; not measured by this offline pipeline |

## Contribution handoff and limitations

Ayden prepared the model input contract, dataset/split method and offline training pipeline. Vince owns packet capture/shared extraction and supplies the candidate data/provenance; Ali independently checks labels and evaluation evidence. Aadi assembles this contribution into the final report. Use actual commits and experiment artifacts when finalizing contribution claims.

A synthetic prepare/train/save/reload/score demo and automated regression tests have exercised software behavior. Artificial patterns do not establish public-data accuracy, generalization or successful live detection. Real-data training remains blocked on a verified manifest, reproducible labels, extraction compatibility and independent split review. Public-data versus lab-traffic distribution differences, spoofed sources, incomplete capture and exclusion bias must be discussed after experiments. MLP comparisons and final conclusions remain future work.

Implementation references: [PR #19](https://github.com/aydsman/ML-DDoS-Detector/pull/19), its `docs/training.md`, `ddos_detector/training.py` and `ddos_detector/training_data.py` at `07f1d1a`; [dataset plan](../dataset-plan.md); [feature contract](../feature-contract.md); [measurement definitions](../measurement-formats.md). External documentation above supports general methods; the project's recorded dependency versions remain the implementation reference.
