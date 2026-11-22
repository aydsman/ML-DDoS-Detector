# Detection and mitigation design

Status: planning decisions recorded from Vince's replies to issues [#1](https://github.com/aydsman/ML-DDoS-Detector/issues/1), [#2](https://github.com/aydsman/ML-DDoS-Detector/issues/2), and [#3](https://github.com/aydsman/ML-DDoS-Detector/issues/3). This document specifies intended behavior; capture adapters, attribution, training, API endpoints, and enforcement are not implemented by these documentation changes.

## Capture scope and windows

- Version one targets inbound IPv4 TCP, UDP, and ICMP traffic to the protected server, lab address `10.10.10.10`, on its lab NIC. The address and interface must be configurable. Dataset victims must be selected from verified dataset metadata, not assumed to use the lab address.
- Vince confirmed IPv4-only version-one scope in issue #5. IPv6 needs separate capture, address-validation, and firewall support before it can be advertised.
- Use one-second, non-overlapping windows by default, controlled by `window_seconds`. Intervals include their start and exclude their end. Packet timestamps are Unix epoch seconds; API timestamps are UTC ISO 8601.
- Approved window origin: `floor(timestamp / window_seconds) * window_seconds`, aligned to Unix epoch time. For example, at duration 1s, timestamps 100.1 and 100.9 belong to [100, 101); 101.0 belongs to [101, 102). Inputs must be time-sorted. A measured empty interval breaks the attribution streak. Capture failure/missing coverage also breaks the streak, but is unavailable data rather than zero traffic. PR #8 implements this epoch alignment and tests boundaries/gaps. Actual offline/live adapter parity and capture-coverage handling remain integration evidence to collect before live use.
- Aggregate features include all selected packets in the window. Do not train the model on per-source groups.

## Stage 1: aggregate detection

Start with a Random Forest producing one attack score and decision per aggregate window. Its score describes combined traffic, never the probability that a particular source is malicious. Use an attack-score threshold of 0.5 as an experimental baseline (attack when score >= threshold). Choose the final value using validation data, considering attack detection and legitimate-client false positives; never tune on the final test. This score threshold is separate from the provisional 80% ground-truth window-label rule.

| Feature | Definition |
| --- | --- |
| packet_rate | Selected packet count / window_seconds, packets/s |
| byte_rate | Sum of selected IP packet lengths / window_seconds, bytes/s |
| syn_count | TCP packets with SYN set and ACK unset |
| syn_ack_ratio | SYN-only count / max(SYN+ACK count, 1); inbound-only interpretation must be checked in lab captures |
| syn_no_ack_share | SYN-only count / max(SYN-only count + ACK-set count, 1) |
| pkt_size_mean | Mean IP packet length in bytes |
| pkt_size_std | Population standard deviation of IP packet lengths in bytes (`pstdev`) |
| unique_src_ips | Number of distinct source addresses in the aggregate window |
| src_ip_entropy | Shannon entropy, base 2, of aggregate source packet counts |
| tcp_share, udp_share, icmp_share | Each protocol's packet count / total selected packet count |

An empty supplied packet list currently returns zero for every feature. Capture failure must not be treated as a measured empty interval. Source diversity features remain aggregate-only; they are not useful as single-source model features.

## Stage 2: source attribution and mitigation policy

Only when stage 1 flags an attack, inspect packet counts grouped by `(src_ip, protocol)` within that same window. Keep TCP, UDP, and ICMP counts separate. These are deterministic attribution rules, not a second ML prediction.

A source is eligible only when all conditions hold:

1. The aggregate window is flagged as attack.
2. Its applicable packet/s or SYN/s threshold is exceeded, together with a minimum traffic-share threshold.
3. The qualifying condition holds for three consecutive windows by default. A benign, nonqualifying, missing, or failed-capture interval breaks the streak. Tune the count using validation/lab evidence.
4. The source is not allowlisted and enforcement limits permit a request.

Approved traffic-share denominator: all selected inbound packets to the protected host, across TCP/UDP/ICMP. The numerator is the source/protocol group packet count. The configurable active-block cap starts at 20 as a provisional lab value. Exact per-protocol packet/s or SYN/s thresholds and minimum share still need lab/validation evidence. Vince proposes streaks per (source IP, protocol), one active block per IP, and expiry measured from the first confirmed block; the convention is one active block per source IP with expiry from its first confirmed installation (repeated detections do not renew it); implementation/reset behavior still needs tests. Until the real NIC, allowlist, and policy settings are verified, remain in monitor-only mode.

Never block the protected server (`10.10.10.10`), legitimate lab client (`10.10.10.20`), loopback, or management/gateway addresses. The attacker address is 10.10.10.30. Vince must supply the actual management/gateway addresses or networks. Validate this allowlist before enabling enforcement.

Defaults: dry-run (`monitor_only`), temporary blocks of 300 seconds, and at most 20 active blocks as a configurable provisional lab cap. Dry-run logs candidates without sending firewall requests. Switching to `automatic` does not bypass eligibility checks. A request is not an active block until the firewall confirms it; expiry must also be confirmed and reconciled.

For spoofed random-source floods, per-source blocks may be ineffective. Protected-port rate limiting is a separate follow-up proposal, not an implemented fallback or an existing dashboard capability.

### Acceptance example for Ali

For three consecutive one-second windows, `10.10.10.30` sends 4,200 SYN packets/s and allowlisted `10.10.10.20` sends 12 normal packets/s. Assume each window is flagged, thresholds are configured below the attacker's observed rate/share, and the block cap is not reached. The attacker contributes about 99.7% of the aggregate packets and becomes eligible after the third window. The legitimate client never becomes eligible. In monitor-only mode neither source is blocked. In automatic mode only the eligible attack source may be requested, subject to final policy checks. This is a controlled example, not a tuned production threshold.

### Event record contract

An aggregate event has `scope: aggregate`, `source_ip: null`, and no attribution evidence. A source event references its aggregate event and carries protocol, packet/SYN rates, packet share, and consecutive-window evidence. The source event's `attack_score` is copied from that aggregate prediction; it is never a per-source model score. See [API contract](api-contract.md) and [mock responses](api-examples.json).

## IP packet size and capture normalization

`Packet.size` is IP packet length in bytes, excluding the link-layer header. For version one, use IPv4 Total Length, including the IPv4 header and transport headers/payload. It is not application payload length or Ethernet frame length.

The definition extends to ordinary IPv6 as fixed IPv6 header plus Payload Length if IPv6 is supported later; IPv6 exceptional cases require explicit handling before support is claimed.

Offline PCAP and live capture must use the same normalization helper. Skip non-IP and out-of-scope packets. For a truncated capture, use the declared IP length only if enough valid header data exists to read and validate it; do not substitute captured byte length. If necessary classification/source fields cannot be read, skip the packet rather than inventing values. Skip malformed IP headers and increment an internal `skipped_packets` diagnostic counter. Its API schema is not specified yet. Vince confirmed that non-first fragments count toward IP bytes and protocol counts but have no readable transport ports/flags. They must not contribute fabricated TCP flag evidence. The shared normalizer now uses Packet.flags = None for unavailable flags, distinct from observed zero. SYN, SYN+ACK and ACK counts use only known flags; other aggregates retain the packet. Skip diagnostics distinguish non-IP, IPv6, truncated header, bad length, and unsupported protocol; final validation/fragment rules and fixtures remain Vince's work. Diagnostics are logs/internal counters, not a new dashboard field.

Verification fixture: an IPv4/TCP packet with 20-byte IP header, 20-byte TCP header, and 20-byte payload is 60 IP bytes. Three such packets in one second must give byte_rate 180, pkt_size_mean 60, and pkt_size_std 0. The feature-level fixture is tested; offline/live adapter parity remains to be implemented and demonstrated.

## Normalization helper and window rules (issue #5)

Implemented by `normalize_ip_packet()` in `ddos_detector/normalize.py` and `window_start()` / `windows()` in `ddos_detector/features.py`, merged in PR #8. Ayden accepted the None representation and policy conventions in the PR review. For the rest, see [feature-contract.md](feature-contract.md) and [dataset-plan.md](dataset-plan.md).

- Packet size is the IPv4 Total Length (IP header, transport header and data). The Ethernet header is excluded, and the captured byte count is never substituted.
- Skipped packets are counted by reason: `non_ip`, `ipv6`, `truncated_header`, `bad_length`, `unsupported_protocol`. The counters are for logs and diagnostics only; the API contract has no new field for them.
- A non-first fragment keeps its size and protocol but has no ports or TCP flags. Its `Packet.flags` is `None` (unknown), as is the flags value of a TCP packet whose TCP header was not captured. A real observed `0` stays `0`, so the two are distinguishable. SYN, SYN-ACK and ACK counts use only packets whose flags are known; all other features still count unknown-flag packets.
- Windows are epoch-aligned: `start = floor(ts / window_seconds) * window_seconds`, start-inclusive and end-exclusive, the same rule offline and live (approved on issue #5). A measured empty window breaks a streak. A capture failure also breaks it but is recorded as `unavailable`, never as zero traffic.
- Agreed policy conventions: absolute per-protocol rate thresholds set from lab/validation data only; streaks per `(src_ip, protocol)`; one block entry per IP, with the 300-second timeout counted from the first block; filtering the dataset to inbound-to-victim packets so training matches inbound-only live capture.
- Baseline decision: retain the twelve currently specified feature formulas for initial validation. With inbound-only capture, syn_ack_ratio counts observed inbound SYN/SYN+ACK and is not a server handshake-completion ratio; it may duplicate syn_count. Evaluate usefulness on validation data. Any removal/redefinition requires a new feature schema and retraining. Do not interpret unknown flags as observed zero.

## Dataset and labels

See [the bounded subset and labeling plan](dataset-plan.md) and [manifest template](dataset-manifest.example.json). The source/download-access check is recorded there; a template is not a verified inventory.

- Train offline on a small raw-PCAP subset of CIC-DDoS2019, initially SYN, UDP, and benign traffic only. DNS/NTP are outside the initial scope. Vince has reported CSV and PCAP archive inventories and local storage locations, recorded in [dataset-plan.md](dataset-plan.md) and [the reported inventory](dataset-inventory-reported.json). The archive byte sizes/hashes are reported, not independently recomputed. Exact selected member names/hashes, direct URLs, ground truth, timezone/victim evidence and independent split assignments still require verification; see [Ali's review status](dataset-review.md).
- Keep raw captures/CSV archives outside Git, preferably outside synced project folders; a gitignored local `data/` is optional. Vince reports `C:\Users\iamno\datasets\cic-ddos2019\`. Commit manifests and small reviewed samples only, never full captures or generated datasets.
- Verify whether official metadata supplies the necessary attack types, attacker/victim identities, and time intervals. An attack schedule alone must not be assumed to identify individual attack packets, especially with spoofed sources.
- A candidate packet label requires verified attack-interval and attacker-to-victim evidence. Traffic lacking trustworthy ground truth stays unlabelled; do not automatically call it benign.
- Use aggregate windows, consistent with stage 1. The per-source alternative in the earlier issue discussion does not apply to this design.
- Provisional attack label: at least 80% of the window's packets are independently attack-labelled, provided ground truth is trustworthy and the window is not mixed/uncertain/boundary under the agreed exclusion rules. Vince will report sensitivity to this label threshold. This is a provisional experiment setting, not the model-score decision threshold.
- Benign label requires verified benign traffic outside all attack intervals, with no attack-labelled or unknown packets. Unknown evidence must never silently become benign.
- Exclude mixed windows below 80%, uncertain/boundary windows, empty windows, and windows inside an attack interval with zero confirmed attack packets until explicit rules are agreed. Count and report exclusions separately. Do not use them as benign training examples or include them in headline metrics.
- Record schedule timezone and conversion to epoch seconds once verified. Preserve capture file, window start/end, label reason, metadata reference, and split in generated records.
- Live lab labels need independent generator logs, source/protocol identities, and recorded start/end times, separate from detector predictions. Apply the same mixed/uncertain rules.

### Issue #3 acceptance checkpoint (November 18)

The [current CIC selection and handoff](cic-acceptance-handoff.md) supplements the historical plan above. Original download/source inventory is in [the reported inventory](dataset-inventory-reported.json); archive/member hashes remain collaborator-reported until source verification.

| Current selection | Intended use | Acceptance status |
| --- | --- | --- |
| `01-12/Syn.csv` with `SAT-01-12-2018_0618` through `_0620` | One candidate SYN run; reported empirical +4-hour conversion | Committed sample is historical v1. Actual reported v2 output and source review pending. |
| `03-11/Syn.csv` with `SAT-03-11-2018_0143`, `_0144` | Reserved collection/run candidate, reported +3-hour conversion | Unverified output and independence; keep out of model/threshold tuning. Truncated `_0145` excluded. |
| `01-12/DrDoS_UDP.csv` with `SAT-01-12-2018_0750` | One-member UDP inspection, chosen November 18 | Actual member identity/hash, offset and packet labels still unknown. No matched plain-UDP benchmark claimed. |
| Independently benign CIC windows | Required class in each approved split | None independently verified; do not infer benign from low rate or unmatched flows. |

Whole-run CIC split approval remains pending: two collections or adjacent archive pieces do not establish three independent splits. The separately accepted lab pilot freezes S1/train, S2/validation and S3/final-test; its acceptance and limitations are in [PR #42](https://github.com/aydsman/ML-DDoS-Detector/pull/42). Keep that pilot distinct from CIC results and keep S3 outcomes out of tuning. Label/exclusion rules, UTC epoch windows, IPv4 byte definitions and all twelve features remain as specified above.

### Splits and leakage

Use training-day captures for training/validation and testing-day captures for final testing only after confirming the selected files and ground truth. Hold out complete captures/runs for validation; do not randomly split neighboring windows. If independent captures are unavailable, revise and document the split before training. Keep final-test labels out of tuning. A held-out attack-type experiment (train SYN, test UDP) is a separate experiment, not the headline split.

Do not feed raw IPs, ports, flow IDs, or timestamps into the model. Keep provenance separately. Fit preprocessing on training data only.

### Dataset completion evidence

Vince and Ali must produce a small inspectable sample (for example five minutes benign and five minutes attack), with feature records, label provenance, mixed/boundary examples, and shared offline/live normalization checks. CSV and PCAP access are now reported by Vince; that does not establish independently reviewed member hashes or valid packet-window labels. Ali's [November 6 review of the candidate SYN join](reviews/issue-3-pr29-review.md) records reconciled candidate counts and required code fixes. Raw-data validity, independently benign examples and whole-run split approval remain pending; see [the evidence review](dataset-review.md).

## Remaining decisions and workflow

Follow-up [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5), assigned to Vince, consolidates unresolved thresholds, capture details, and dataset verification. The design/fixture acceptance for issues #1/#2 is closed and recorded in [contract acceptance](contract-acceptance.md); dataset issue #3 remains open. Ayden accepted the redesigned sample frontend through PR #21; real API freshness/history/error behavior still needs backend integration. Review order agreed on October 26: docs and fixtures PR into development first, then lab settings/measurements, then dataset verification. Ali independently checks fixtures and labelled samples. See [feature contract](feature-contract.md) for ordered ML inputs and component boundaries.

The policy settings proposal (thresholds method, block rules, lab interface and allowlist, window rule, SYN/ACK evidence) is in [policy-proposal.md](policy-proposal.md); it sets no threshold values because the evidence does not exist yet.

Approved decisions are recorded in [Ayden's issue #5 reply](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428534359). Documenting them does not complete the outstanding acceptance evidence.

Work and integration happen on `development`. Promote tested and reviewed changes to `main` through a pull request.

## October 30 issue review and remaining evidence

| Issue | Ayden decision / existing evidence | Required next evidence and owner |
| --- | --- | --- |
| #3 dataset | SYN/UDP/benign scope; MSSQL excluded; provisional folder-based split; reported CSV inventory linked above | Vince: PCAP selection, metadata/timezone and independent runs, reproducible labels and sample. Ali: independent label/exclusion review. Ayden: approve verified split before training. |
| #2 packet size | IPv4 Total Length, no Ethernet; unknown flags None; normalizer and 60-byte arithmetic fixtures merged in #8 | Vince: same fixture through actual offline and live-style adapters, inbound filter, skip reasons and coverage evidence. Ali: verify expected results. Helper tests alone do not prove adapter parity. |
| #1 attribution | Aggregate model plus deterministic source/protocol policy, all-inbound share denominator, three windows, allowlist, monitor-only, confirmed-only active blocks; acceptance example above | Ali: review acceptance example. Vince: validation/lab threshold/share evidence and verified runtime allowlist. Ayden: approve settings. Live mitigation remains pending implementation, independent of this planning decision. |
| #5 integration | Retain version-one feature formulas and None flags; storage approved; #15 promotion policy merged | Vince: runtime NIC/allowlist, adapter parity/coverage, lab/validation policy measurements and dataset evidence; Ali reviews fixtures/labels. Track missing evidence explicitly rather than closing the tracker. |

These decisions do not claim a working model, packet adapters or firewall integration. Issues remain open while their acceptance evidence or associated documentation review is pending.
