# Attribution and packet-size contract acceptance — November 8

Reviewed by Ayden as project owner, taking over the available acceptance work originally assigned to Ali. This closes the planning/known-fixture scope of issues #1 and #2. It is not a peer approval, a live-NIC experiment, a tuned policy or a dataset ground-truth review.

## Issue #1: aggregate detection and source attribution

The accepted design in `design.md`, `feature-contract.md` and `api-contract.md` keeps a single aggregate prediction per inbound one-second protected-server window. The separate deterministic grouping key is `(source IP, protocol)`. Source-event scores copy the aggregate event score; they are not probabilities that an individual source is malicious. An aggregate attack event alone never makes every source block-eligible.

Owner-checked acceptance example, using three consecutive flagged windows:

| Source | Traffic per second | Window share | Rule outcome |
| --- | --- | --- | --- |
| `10.10.10.30` | 4,200 SYN packets | 4,200 / 4,212 = 99.7151% | Eligible only after all validated rate/share conditions hold for the third consecutive window and runtime allowlist/cap checks pass |
| `10.10.10.20` | 12 legitimate HTTP packets | 12 / 4,212 = 0.2849% | Allowlisted; always ineligible regardless of aggregate prediction |

These numbers illustrate the rule; no actual rate/share thresholds are validated by this arithmetic. Monitor-only requests no firewall action for either source. Automatic mode may request `.30` only after the additional checks; it becomes a displayed block only after confirmed installation. Empty, unavailable or nonqualifying windows reset the streak. One IP has at most one confirmed block; TTL begins at first confirmed installation. Policy/firewall implementation, runtime allowlist verification and false-block lab tests remain under issue #5 and later integration tasks. This record accepts the design/example, not implemented enforcement.

## Issue #2: packet size and adapter parity

Version one means **IPv4 Total Length in bytes**, including IP/transport headers and payload, excluding Ethernet/padding. Usable truncated captures retain the declared length. Invalid/incomplete headers are skipped with reasons. Unknown flags are `None`; IPv6 is deferred. Population standard deviation is used.

On November 8, an independently byte-built Ethernet PCAP with three 60-byte IPv4 TCP SYN packets at epoch 100.1, 100.2 and 100.3 was processed separately through `offline.extract_pcap` and `LivePipeline.run(read_pcap(...))`. Both produced exactly one `[100,101)` record, no skips, and the literal vector:

| Feature | Expected and observed |
| --- | --- |
| packet_rate / byte_rate | 3 packets/s / 180 bytes/s |
| syn_count / syn_ack_ratio / syn_no_ack_share | 3 / 3 / 1 |
| pkt_size_mean / pkt_size_std | 60 bytes / 0 bytes |
| unique_src_ips / src_ip_entropy | 1 / 0 bits |
| tcp_share / udp_share / icmp_share | 1 / 0 / 0 |

PR #25's saved synthetic fixtures independently verify all twelve ordered values, original byte hashes, malformed/truncated packets, fragments, filtered frames, epoch boundaries and idle ticks through normalization, offline and replay paths. PR #28's independent Scapy/tshark references provide another check against literal arithmetic. An absent interval remains absent; it is not converted into a measured zero or a coverage claim.

This satisfies the documented size definition, manually expected statistics, shared fixture/provenance and offline/live-style adapter parity. Physical AF_PACKET/NIC behavior, kernel drops, clock health, capture completeness and service measurements remain unverified here and stay tracked in issue #5. They are not prerequisites for deciding what packet size means.
