# Detection and mitigation design

Status: planning decisions recorded from Vince's replies to issues [#1](https://github.com/aydsman/ML-DDoS-Detector/issues/1), [#2](https://github.com/aydsman/ML-DDoS-Detector/issues/2), and [#3](https://github.com/aydsman/ML-DDoS-Detector/issues/3). This document specifies intended behavior; capture adapters, attribution, training, API endpoints, and enforcement are not implemented by these documentation changes.

## Capture scope and windows

- Version one targets inbound IPv4 TCP, UDP, and ICMP traffic to the protected server, lab address `10.10.10.10`, on its lab NIC. The address and interface must be configurable. Dataset victims must be selected from verified dataset metadata, not assumed to use the lab address.
- Vince confirmed IPv4-only version-one scope in issue #5. IPv6 needs separate capture, address-validation, and firewall support before it can be advertised.
- Use one-second, non-overlapping windows by default, controlled by `window_seconds`. Intervals include their start and exclude their end. Packet timestamps are Unix epoch seconds; API timestamps are UTC ISO 8601.
- Approved window origin: `floor(timestamp / window_seconds) * window_seconds`, aligned to Unix epoch time. For example, at duration 1s, timestamps 100.1 and 100.9 belong to [100, 101); 101.0 belongs to [101, 102). Inputs must be time-sorted. A measured empty interval breaks the attribution streak. Capture failure/missing coverage also breaks the streak, but is unavailable data rather than zero traffic. The current `windows()` helper still anchors to the first packet; Vince must implement epoch alignment and demonstrate offline/live parity in his docs/fixtures and extractor work.
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

Approved traffic-share denominator: all selected inbound packets to the protected host, across TCP/UDP/ICMP. The numerator is the source/protocol group packet count. The configurable active-block cap starts at 20 as a provisional lab value. Exact per-protocol packet/s or SYN/s thresholds and minimum share still need lab/validation evidence. Vince proposes streaks per (source IP, protocol), one active block per IP, and expiry measured from the first confirmed block; cross-protocol reset/deduplication behavior still needs review and tests. Until the real NIC, allowlist, and policy settings are verified, remain in monitor-only mode.

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

Offline PCAP and live capture must use the same normalization helper. Skip non-IP and out-of-scope packets. For a truncated capture, use the declared IP length only if enough valid header data exists to read and validate it; do not substitute captured byte length. If necessary classification/source fields cannot be read, skip the packet rather than inventing values. Skip malformed IP headers and increment an internal `skipped_packets` diagnostic counter. Its API schema is not specified yet. Vince confirmed that non-first fragments count toward IP bytes and protocol counts but have no readable transport ports/flags. They must not contribute fabricated TCP flag evidence. The adapter still needs to distinguish unavailable flags from a real observed zero value; the current Packet.flags integer alone cannot express this distinction. Skip diagnostics distinguish non-IP, IPv6, truncated header, bad length, and unsupported protocol; final validation/fragment rules and fixtures remain Vince's work. Diagnostics are logs/internal counters, not a new dashboard field.

Verification fixture: an IPv4/TCP packet with 20-byte IP header, 20-byte TCP header, and 20-byte payload is 60 IP bytes. Three such packets in one second must give byte_rate 180, pkt_size_mean 60, and pkt_size_std 0. The feature-level fixture is tested; offline/live adapter parity remains to be implemented and demonstrated.

## Dataset and labels

See [the bounded subset and labeling plan](dataset-plan.md) and [manifest template](dataset-manifest.example.json). The source/download-access check is recorded there; a template is not a verified inventory.

- Train offline on a small raw-PCAP subset of CIC-DDoS2019, initially SYN, UDP, and benign traffic only. DNS/NTP are outside the initial scope. Exact filenames, sizes, checksums, official download URLs, disk needs, and storage location are still unverified.
- Keep captures under gitignored `data/`; never commit captures or generated datasets to Git.
- Verify whether official metadata supplies the necessary attack types, attacker/victim identities, and time intervals. An attack schedule alone must not be assumed to identify individual attack packets, especially with spoofed sources.
- A candidate packet label requires verified attack-interval and attacker-to-victim evidence. Traffic lacking trustworthy ground truth stays unlabelled; do not automatically call it benign.
- Use aggregate windows, consistent with stage 1. The per-source alternative in the earlier issue discussion does not apply to this design.
- Provisional attack label: at least 80% of the window's packets are independently attack-labelled, provided ground truth is trustworthy and the window is not mixed/uncertain/boundary under the agreed exclusion rules. Vince will report sensitivity to this label threshold. This is a provisional experiment setting, not the model-score decision threshold.
- Benign label requires verified benign traffic outside all attack intervals, with no attack-labelled or unknown packets. Unknown evidence must never silently become benign.
- Exclude mixed windows below 80%, uncertain/boundary windows, empty windows, and windows inside an attack interval with zero confirmed attack packets until explicit rules are agreed. Count and report exclusions separately. Do not use them as benign training examples or include them in headline metrics.
- Record schedule timezone and conversion to epoch seconds once verified. Preserve capture file, window start/end, label reason, metadata reference, and split in generated records.
- Live lab labels need independent generator logs, source/protocol identities, and recorded start/end times, separate from detector predictions. Apply the same mixed/uncertain rules.

### Splits and leakage

Use training-day captures for training/validation and testing-day captures for final testing only after confirming the selected files and ground truth. Hold out complete captures/runs for validation; do not randomly split neighboring windows. If independent captures are unavailable, revise and document the split before training. Keep final-test labels out of tuning. A held-out attack-type experiment (train SYN, test UDP) is a separate experiment, not the headline split.

Do not feed raw IPs, ports, flow IDs, or timestamps into the model. Keep provenance separately. Fit preprocessing on training data only.

### Dataset completion evidence

Vince and Ali must produce a small inspectable sample (for example five minutes benign and five minutes attack), with feature records, label provenance, mixed/boundary examples, and shared offline/live normalization checks. No dataset access or validity is claimed until this evidence exists.

## Remaining decisions and workflow

Follow-up [issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5), assigned to Vince, consolidates unresolved thresholds, capture details, and dataset verification. Original issues #1-#3 remain open until their completion evidence is satisfied. Aadi must still review display fields, history limits, and backend error/stale-data behavior with Ayden. Review order agreed on October 26: docs and fixtures PR into development first, then lab settings/measurements, then dataset verification. Ali independently checks fixtures and labelled samples. See [feature contract](feature-contract.md) for ordered ML inputs and component boundaries.

Approved decisions are recorded in [Ayden's issue #5 reply](https://github.com/aydsman/ML-DDoS-Detector/issues/5#issuecomment-6428534359). Documenting them does not complete the outstanding acceptance evidence.

Work and integration happen on `development`. Promote tested and reviewed changes to `main` through a pull request.
