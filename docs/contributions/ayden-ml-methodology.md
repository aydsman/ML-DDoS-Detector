# Ayden's report contribution: architecture and machine learning

Author: Ayden Sendrea. Updated November 21, 2026 for Aadi's report assembly.

**Evidence boundary.** The controlled-lab Random Forest has been trained, saved,
reloaded and evaluated on S2 validation windows. An offline MLP and rate-rule
comparison is also complete. These are narrow lab validation results, not
CIC-DDoS2019 benchmark results, final-test results or proof of live protection.
The lab review is recorded in [issue #3](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6987025978);
the baseline and comparison are under peer review in
[PR #42](https://github.com/aydsman/ML-DDoS-Detector/pull/42) and
[PR #44](https://github.com/aydsman/ML-DDoS-Detector/pull/44).
Aadi can use this contribution for the architecture, method, validation and
limitations sections, preserving these qualifications.

## Architecture and responsibility

The pipeline captures selected inbound packets, aggregates one-second windows,
validates twelve ordered features, loads the saved model and produces an
aggregate attack score. A bounded state store exposes health, traffic metrics,
detections and confirmed block records through four read-only FastAPI endpoints.
The four-view dashboard presents those responses with explicit sample,
historical, unavailable and stale-data states.

The model scores the combined traffic window. It does not identify an attack
type or prove a particular source IP is malicious. A separate deterministic
policy uses source/protocol counts, rate/share thresholds, repeated-window
requirements and an allowlist to decide whether a source is eligible for a
temporary block. Those diagnostic counts are not additional model features.
A detection, a block request and a verified firewall rule are distinct events.

The live monitor/API entry point is implemented in
[PR #43](https://github.com/aydsman/ML-DDoS-Detector/pull/43).
Vince completed the simultaneous trained-model benign live capture/API run.
The owner accepted its bounded evidence in
[issue #48](https://github.com/aydsman/ML-DDoS-Detector/issues/48), independently
matching API/audit records and reproducing all 46 Run 03 packet-derived scores
and 34 unique available byte-rate points. Final teammate review/merge of
PR #43 remains pending; this acceptance does not establish attack accuracy
or active protection.
A saved-window replay checked 550 S2 predictions through the API against the
monitor's scores. That is offline integration evidence.
The automatic runner in
[PR #47](https://github.com/aydsman/ML-DDoS-Detector/pull/47) remains a draft;
validated enforcement settings and live acceptance are pending, and the
dashboard does not yet consume that runner's automatic state.

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

## Controlled-lab data, labels and splits

Public CIC-DDoS2019 SYN/UDP/benign selection remains unresolved in
[issue #3](https://github.com/aydsman/ML-DDoS-Detector/issues/3).
Flow-level CSV fields cannot replace the twelve packet-window features.
The completed baseline instead uses the explicitly narrowed controlled-lab
pilot; public attack captures and lab benign traffic were not combined.

Whole sessions S1/S2/S3 were assigned to train/validation/final test. Within each,
the first 300 eligible windows per binary class in timestamp order were retained,
using smaller classes as supplied. Adjacent windows from a session never cross
splits. Three sessions on the same lab network are not broad independent
workloads.

| Split | Session | Benign | SYN-labelled attack | UDP-labelled attack | Label exclusions |
| --- | --- | ---: | ---: | ---: | ---: |
| Training | S1 | 300 | 163 | 90 | 151 |
| Validation | S2 | 300 | 162 | 88 | 153 |
| Held-out test, unscored | S3 | 300 | 162 | 138 | 91 |

The cap additionally set aside 227/228/228 benign and 0/0/12 attack windows for
S1/S2/S3 respectively. These cap removals differ from label exclusions.
The retained labelled file contains 237 boundary and 158 mixed exclusions.
S3 counts describe the frozen split inventory, not evaluated performance.

The label protocol excludes unknown coverage/labels, capped source counts,
empty windows, interval boundaries and ambiguous mixtures. For eligible
windows, independently attack-labelled packets comprising at least 80% of
selected packets qualify as attack; fully benign windows must be outside
verified attack intervals. This 80% ground-truth rule is separate from the
0.5 model decision threshold. In this lab, inbound resets from a logged attacker
source during its run contribute to attack labels; this can create an easy
classification shortcut rather than prove robust SYN-flood recognition.

Fifteen packet-export windows reproduced all twelve features and their labels.
Full PCAP checksums remain collaborator-reported: this review did not replay
or independently rehash all original PCAP bytes. The November 20 metadata
correction excluded stale/orphan S3 provenance records and corrected the
reconciliation text to the original 2.5-second coverage slack. It did not
replace the frozen reviewed windows, splits or model, and it did not score S3.
Details and checksum verification are retained in
[PR #42](https://github.com/aydsman/ML-DDoS-Detector/pull/42).

## Models, preprocessing and validation

The saved Random Forest uses 100 trees, seed 3670, one worker and balanced
class weights derived from S1. It performs no scaling or imputation.
Its aggregate attack-class probability is classified at the recorded 0.5
baseline threshold; it is not a calibrated confidence or source attribution.

The comparison MLP is a training-only StandardScaler followed by one hidden
layer of 16 units, L-BFGS, alpha 0.0001, maximum 1,000 iterations and seed 3670.
Validation candidates 0.3, 0.5 and 0.7 tied on F1; the declared tie breakers
(fewer false positives, closest to 0.5, then lower threshold) selected 0.5.
There was no convergence warning. Reloaded probabilities matched exactly.

The experimental aggregate rate rule flags packet_rate > 42 packets/s, the
largest benign training rate. This is a lab comparison cutoff, not a
validated per-source firewall setting.

All three methods used the same 550 eligible S2 validation windows:

| Method | TN | FP | FN | TP | Attack precision | Attack recall | F1 | Benign false-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest, 0.5 | 300 | 0 | 0 | 250 | 1.0000 | 1.0000 | 1.0000 | 0.00% |
| StandardScaler + MLP, 0.5 | 300 | 0 | 0 | 250 | 1.0000 | 1.0000 | 1.0000 | 0.00% |
| Aggregate rate > 42 packets/s | 296 | 4 | 0 | 250 | 0.9843 | 1.0000 | 0.9921 | 1.33% |

Confusion matrices use actual classes as rows, predicted classes as columns,
in benign/attack order. Undefined metric denominators are represented as null.
The equal learned-model validation scores do not establish superiority or
generalization. There are only 550 windows from one validation session;
correlated windows and exclusions limit the interpretation.

## Reproducibility and retained artifacts

The loader validates feature order, schema, numeric type, one-second epoch
windows, packet-size definition, checksum, matching Python major/minor and
exact ML library versions. Trusted local joblib packages only are used.
Save/reload equality establishes reproducibility in this environment, not
cross-machine live acceptance.

Recorded runtime: Python 3.12.10, NumPy 2.5.4, scikit-learn 1.9.1,
SciPy 1.18.1 and joblib 1.6.0. Training revision was d53fe7b;
comparison implementation was f4a3492. Package metadata retains those identities.

| Frozen artifact | SHA-256 |
| --- | --- |
| reviewed-windows.json | abfb8270d4120cda5aaf7d41245e8efaa8078c7c599ae1da674994ac0cb54519 |
| reviewed-splits.json | fd42c0d424a3fc61d51bec9c1f03b56f313c4021036bdaad8de7c8453dbefc05 |
| Random Forest model.joblib | 44f2ae879b63414c8af7d7c1165e7a0d462c9545f6190f7a8a7b2f00aa9e9fe7 |
| Comparison mlp.joblib | 4ccca7213657ada1e114d5df0a79b28c6e26de9ffc78a113e7f7491bb6120393 |

Windows, serialized models, raw scores and raw timing samples stay in ignored
results directories or the private OneDrive handoff. Commit bounded reports,
configuration and hashes. These are frozen candidate identities; final
deployment-model selection is still pending peer review and final evaluation.

## Working model choice

The Random Forest remains the existing W3 handoff baseline: its saved-artifact
guards, reload/scoring path and offline monitor/API replay have been exercised.
The MLP ties its eligible S2 validation scores and is a comparison candidate.
This is a provisional integration choice, not evidence that the forest is
more accurate or faster. Final selection requires independent review,
reproducible settings and the agreed evaluation; neither the validation tie
nor local timing alone establishes the best deployed detector.

## Inference-time measurement

The validation-only procedure in [model-comparison.md](../model-comparison.md)
loads these saved models without retraining or changing thresholds. It times
warm batch-size-one predict_proba calls on the same prebuilt float64 windows.
The MLP timing includes its scaler; neither timing includes extraction,
one-second window accumulation, record validation, logging, HTTP or firewall
work. Laptop timing cannot establish VM overhead or end-to-end detection delay.

| Model | Median per window | p95 per window | Timed calls |
| --- | ---: | ---: | ---: |
| Saved Random Forest | 21.807 ms | 38.519 ms | 2,750 |
| Saved StandardScaler + MLP | 1.162 ms | 2.195 ms | 2,750 |

Measured November 21 on the i7-8650U Windows laptop, five passes over the same
550 S2 windows after 50 warm-up calls per model, one native thread, forest
n_jobs=1. The MLP was faster in this local scoring workload. Background load
and power state were not controlled, and the dashboard preview remained
running. The [bounded record](../reviews/inference-benchmark-2026-11-21.json)
retains per-round statistics, environment, hashes and clean tool revision
475c447. Frozen data/model bytes are unchanged; S3 remains unscored.

## Remaining evaluation and handoff

- Complete peer review of the lab baseline and comparison.
- Local inference timing and repeated-run summaries are recorded above.
  Target-VM timing and full capture-to-detection latency remain separate work.
- Agree the final candidate/configuration with Ali using validation evidence,
  then run S3 once under the agreed frozen protocol. Do not tune against S3.
- Complete final teammate review and merge of PR #43. The trained-model
  benign live evidence in issue #48 has been independently accepted.
- Validate source-policy settings and repeated mitigation/service experiments
  with Ali, Mujtaba and Vince. Detection delay, false blocks, legitimate-client
  availability, recovery, resource overhead and capture loss remain unmeasured
  by this offline comparison.
- Aadi assembles the report; Ayden supplies architecture/ML evidence, Ali owns
  independent evaluation, Vince supplies capture/deployment evidence, and
  Mujtaba supplies generation/enforcement evidence.

The current lab workload is narrow, S3 benign traffic rates differ, reset-based
labels may expose shortcuts, and mixed/uncertain/capped or empty windows are
excluded. Spoofing, other networks and untested attack profiles remain outside
the demonstrated scope. Synthetic demos establish software behavior only.
Neither these lab validation results nor historical block records establish
that the finished system currently protects a live server.
