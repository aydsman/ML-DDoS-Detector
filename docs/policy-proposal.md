# Policy settings and capture behavior: proposal for issue #5, section 1

Owner: Vince. Reviewers: Ayden (policy/API), Ali. Status: owner-accepted design/defaults; thresholds and runtime allowlist validation remain pending. Nothing here enables enforcement, loads a model or claims a tuned threshold. The machine-readable defaults are in [policy-defaults.json](policy-defaults.json); no code reads that file yet. Settled decisions are in [design.md](design.md) and the issue #5 replies; this document adds the missing numbers' method, the block bookkeeping rules and the lab facts.

Protected-port rate limiting is a separate proposal and is not covered here.

## 1. Evidence available today, and what it cannot support

Vince reports computing all figures below on 2026-11-08 from the saved lab PCAPs under `data/lab-runs/` (inbound to 10.10.10.10, one-second epoch windows, the repository's own `iter_packets`) and from the reported candidate windows in `docs/samples/cic-syn-0618-0620/windows.json` (PR #29, training-day only, labels and offsets not independently verified). No final-test (03-11) data was used. Vince reports no output of `tools/collect_baseline.py` in his checkout/lab folder. The raw lab inputs and runtime command outputs are unavailable to this owner review, so the numerical/runtime observations remain collaborator-reported; a source list is not independent reproduction.

| Evidence | What it shows | Limits |
| --- | --- | --- |
| Legitimate HTTP client, 2 runs (`http-client-2026-10-28-rerun`) | One source (10.10.10.20), TCP only. 72 and 57 windows. Total inbound pps: median 10 and 8, maximum 18 in both. SYN-only: at most 2 per second. | One client, one nginx page, target 5 req/s (about 4 achieved). No concurrency, no larger load. Lab VM timers jitter up to about 3 s. |
| Controlled SYN, 3 runs (`pr16-syn-run1`, `syn-run2`, `ctrlc-syn`) | One source (10.10.10.30). 10 SYN/s offered; the source's TCP packets are 20 per second because its inbound RSTs count too. Share of all inbound packets: 1.0 in every window. | Generator test rate, not a flood. The offered SYN-only rate is 10/s, while the observed source packet rate includes RSTs and is 20/s. Do not compare those different quantities as though both were total packet rates. |
| Controlled UDP, 3 runs (`pr16-udp-run1`, `udp-run2`, `ctrlc-udp`) | One source, 10 UDP packets/s, share 1.0. | Same: a pipeline test, not a flood. |
| Inbound ICMP from 10.10.10.30 | 1 packet/s in 2 windows of each of four scenario captures. | Low-rate ICMP observation; no independently labelled ICMP flood or benign-window evidence is established here. |
| CIC-DDoS2019 candidate SYN windows (PR #29) | 8 candidate attack windows, one source, TCP share about 1.0. 19,062 to 20,912 packets/s per window, all but a handful SYN-only (SYN-only 19,060 to 20,912). | Training-day, one run, unreviewed ground truth, unresolved time offset. No benign windows, no UDP windows. Not a lab measurement. |

What this means: the largest benign rate we have measured is 18 pps total from a single client, and the attack rates we have are either 10 pps (lab generator) or about 20,000 SYN/s (unreviewed public data). Any number between about 18 and 19,000 would be a guess, so this proposal sets none. There is no evidence at all for UDP or ICMP flood rates, for any minimum share, or for a legitimate client running next to an attacker.

### Lab runs added on 2026-11-08 (reported by Vince; raw files not in Git)

Run on the three lab VMs with the same normalization and one-second epoch windows as above. Every capture is `tcpdump -i enp0s8 'host 10.10.10.10'` on `ddos-server` with 0 kernel drops. No sudo was needed on the server or client; the attacker ran `ddos_detector.scenarios` as root. Raw files are in `data/lab-runs/policy-2026-11-08/` on Vince's PC.

Benign load: the legitimate client at 20, 50 and 100 requests/s offered (30 s each, concurrency 4, 8, 16), reaching 5.3, 38.3 and 96.0 achieved requests/s.

| Offered / achieved requests/s | Client packets/s per window: median, max | Client SYN-only/s: max |
| --- | --- | --- |
| 20 / 5.3 | 11, 24 | 1 |
| 50 / 38.3 | 54, 62 | 1 |
| 100 / 96.0 | 100, 104 | 1 |

Attack ladder with the same client running in the background (about 22 packets/s median, 42 at most in client-only windows). Each row is one 20 s run, except the 1000 packets/s rows (10 s, and the sender reached 817 SYN/s and 900 UDP packets/s because of timer lag). Windows at the start and end of a run are dropped because they hold part of the neighbouring interval, so each row uses 19 windows (9 for the 1000 rows). The attacker's TCP rate counts its inbound RSTs, so it is about twice its SYN rate.

| Scenario | Offered | Attacker packets/s per window: min to max | Attacker SYN-only/s: min to max | Attacker share of all inbound packets: min | Client share: max |
| --- | --- | --- | --- | --- | --- |
| SYN | 50 | 100 to 100 | 50 to 50 | 0.758 | 0.242 |
| SYN | 200 | 388 to 402 | 194 to 201 | 0.934 | 0.066 |
| SYN | 500 | 956 to 1000 | 478 to 500 | 0.964 | 0.036 |
| SYN | 1000 | 1548 to 1802 | 774 to 902 | 0.977 | 0.023 |
| UDP | 50 | 50 to 50 | 0 | 0.641 | 0.359 |
| UDP | 200 | 193 to 200 | 0 | 0.870 | 0.130 |
| UDP | 500 | 462 to 500 | 0 | 0.931 | 0.069 |
| UDP | 1000 | 848 to 923 | 0 | 0.955 | 0.045 |

What this does and does not show:

- TCP packets/s alone does not separate the cases: the weakest SYN run (100 packets/s) is no higher than the benign client's 104 packets/s at high load. SYN-only/s does separate them in these runs: the benign client never exceeded 2 SYN-only/s (1 at high load) and the weakest attack was 50. Any value in that gap would be consistent with this data, and none is proposed here.
- The benign SYN figure above is a lower bound for real clients: the HTTP client reuses connections. Runs with a new connection per request are in the next subsection and show a much higher SYN-only/s.
- This table had no benign UDP or ICMP; those are measured in the next subsection.
- Minimum share: in the mixed windows the attacker's share was at least 0.64 and the client's at most 0.36 (UDP at 50 packets/s). One share value between those would have separated them here, but only for a single client at about 22 packets/s and a single attacker, so this is not enough to set it.
- Single-source runs only; no multi-source or spoofed run, and no validation split. These are lab runs for the method in section 2, not tuned results.

### Benign and attack validation runs, session 2 (2026-11-08 and 2026-11-11)

Done to fill the gaps listed above. Every run has its own capture (`tcpdump -i enp0s8 'host 10.10.10.10'` on `ddos-server`, 0 kernel drops in all 61), client and attacker logs, and clock samples before and after. Raw files: `data/lab-runs/policy-2026-11-08b/` on Vince's PC (outside Git, 111 MB); summaries in its `analysis/`. Windows are one-second epoch windows from the server capture timestamps, computed with `tools/lab_window_summary.py` (first and last window of a capture dropped; for attack sources the source's own first and last window dropped as well). Nothing from 03-11 was used. These are lab runs by one person on one set of VMs, not independently reproduced.

**Benign senders** (client 10.10.10.20, 20 s per run, two separate whole runs per rate, `b1` and `b2`). Values are the larger of the two runs; the paced Python senders reached the offered rate except where noted.

| Sender | Offered per s | Source packets/s: median, max | SYN-only/s: max |
| --- | --- | --- | --- |
| New TCP connection per request | 5 | 25, 50 | 10 |
| | 20 | 100, 115 | 23 |
| | 50 | 250, 295 | 59 |
| | 100 | 500, 534 | 107 |
| | 200 | 1000, 1110 | 222 |
| | 400 | about 2000, 2270 | 454 |
| UDP datagrams | 10 | 10, 14 | 0 |
| | 50 | 50, 57 | 0 |
| | 200 | 200, 214 | 0 |
| | 500 | 500, 501 | 0 |
| | 1000 | 1000, 1243 | 0 |
| | 2000 | 2000, 2356 | 0 |
| ICMP echo | 1 | 1, 1 | 0 |
| | 5 | 5, 10 | 0 |
| | 20 | 20, 25 | 0 |
| | 100 | 100, 112 | 0 |
| | 500 | 500, 577 | 0 |

A client that opens a new connection per request sends about 5 packets and 1 SYN-only per request, so its SYN-only/s is about its request rate. The earlier "at most 2 SYN-only/s" figure was only because that HTTP client reused connections.

**Attack runs**, each its own capture. "Mixed" runs have the HTTP client in the background (about 20 requests/s, concurrency 4). Two whole repetitions (`v1`, `v2`). SYN and UDP used `ddos_detector.scenarios` from 10.10.10.30. The scenario tool has no ICMP and no multi-source mode, so the ICMP and multi-source runs used `hping3` on the attacker, with real extra addresses 10.10.10.31 to 10.10.10.40 added to its `enp0s8` for the runs and removed afterwards (not spoofed). Ranges are over both repetitions, trimmed windows.

| Scenario | Offered | Attacker packets/s | Attacker SYN-only/s | Attacker share of all inbound |
| --- | --- | --- | --- | --- |
| SYN, mixed | 50 | 108 to 110 | 54 to 55 | 0.71 to 0.90 |
| | 200 | 420 to 434 | 210 to 217 | 0.91 to 0.97 |
| | 500 | 751 to 1081 | 375 to 541 | 0.96 to 0.99 |
| | 1000 (10 s) | 1493 to 2072 | 747 to 1036 | 0.98 to 0.99 |
| UDP, mixed | 50 | 54 to 55 | 0 | 0.60 to 0.78 |
| | 200 | 202 to 217 | 0 | 0.82 to 0.96 |
| | 500 | 478 to 541 | 0 | 0.92 to 0.98 |
| | 1000 (10 s) | 923 to 1026 | 0 | 0.96 to 0.98 |
| SYN, alone | 50 / 1000 | 108 to 110 / 1617 to 2045 | 54 to 55 / 809 to 1022 | 1.0 |
| UDP, alone | 50 / 1000 | 54 to 55 / 953 to 1029 | 0 | 1.0 |
| ICMP, alone (hping3) | 50 | 51 to 52 | 0 | 1.0 |
| | 200 | 183 to 193 | 0 | 1.0 |
| | 1000 (10 s) | 698 to 764 | 0 | 1.0 |

The attacker's TCP packets/s is about twice its SYN-only/s because its inbound RSTs count. The observed UDP rate at 200 offered (about 216) is higher than the sender reported (198 mean); I did not find the cause.

**Multi-source** (hping3, one run each, HTTP client in the background, 20 s):

| Scenario | Sources | Per-source packets/s | Per-source SYN-only/s | Per-source share of all inbound |
| --- | --- | --- | --- | --- |
| SYN | 5 x 100 offered | 196 to 208 | 98 to 104 | 0.19 to 0.20 |
| SYN | 10 x 50 offered | 94 to 107 | 47 to 54 | 0.095 to 0.10 |
| UDP | 5 x 100 offered | 99 to 105 | 0 | 0.18 to 0.20 |
| UDP | 10 x 50 offered | 51 to 53 | 0 | 0.09 to 0.10 |

**What the data supports:**

- No clear gap on any rate. For every protocol the benign ceiling measured here is above the lowest attack rate I sent: TCP SYN-only/s benign 454 vs attack 54; TCP packets/s 2270 vs 108; UDP packets/s 2356 vs 54; ICMP packets/s 577 vs 51. So `packet_rate_thresholds` and `syn_rate_threshold` stay `null`. The benign numbers are also not true ceilings: the highest rates I tried were 400 requests/s, 2000 UDP packets/s and 500 ICMP/s with paced Python senders, and a real client could go higher.
- Share does not separate benign from attack. A lone benign client has share 1.0, the same as a lone attacker. In the single-attacker mixed runs the attacker's share was at least 0.60 (UDP at 50 packets/s), but with 5 or 10 sources each source's share is only about 0.2 or 0.1, so a `min_share` above 0.2 would never qualify a distributed attack, as described in section 2. Per-source rates in the multi-source runs (about 50 to 105 TCP packets/s, 47 to 54 SYN-only/s with 10 sources) are within what a benign client at 20 to 50 requests/s produces.
- One observation, not a proposed threshold: the SYN-only fraction of a source's TCP packets was about 0.2 for the new-connection benign client (for example 107 of 500) and 0.50 for the SYN attacker in every run. In this lab the 0.5 is because the kernel's RSTs are counted; against spoofed or silent sources it would be higher. This is a possible feature or condition for Ayden to consider, with one generator on one lab.

**Limits and problems in these runs:**

- Single lab, one benign generator per protocol (paced Python), one attack generator for SYN/UDP and hping3 for ICMP and multi-source. SYN, UDP and benign rates have two repetitions; the multi-source, ICMP and "alone" runs have one.
- VM clocks: after the VMs were reset the client and attacker clocks were about 28 hours behind the host and the server (the server matched the host within about 1.5 s). The analysis uses only server capture timestamps, but the client and attacker timestamps in their own logs cannot be compared with the captures. During `b2-udp-500` the VM clocks jumped by about 6 hours (the client log shows `achieved_per_s` 0.44). The capture still shows 500 packets/s with one low window (220), and its maximum is unaffected.
- The client and attacker VMs hung on the first boot of this session (no SSH, boot output stopped) and were reset with `controlvm reset`; the first attempt to start the attacker script also stopped waiting for a sudo password, so the attack runs happened on 2026-11-11 instead of 2026-11-08.
- The 1000 packets/s runs are 10 s (scenario tool cap of 10,000 packets), so each has 8 to 9 usable windows.

## 2. Thresholds and minimum share

### Rule shape (proposed)

A source/protocol group `(src_ip, protocol)` qualifies in a window when the window is flagged as an attack and both hold:

- Rate: the group's packets per second is strictly greater than that protocol's `packet_rate_thresholds` value, or, for TCP, its SYN-only packets per second is strictly greater than `syn_rate_threshold`. SYN-only means SYN set, ACK unset, flags known.
- Share: group packets divided by all selected inbound packets in that window is greater than or equal to `min_share`.

A threshold left unset (`null`) never qualifies. So with the defaults in [policy-defaults.json](policy-defaults.json) no source can ever become eligible, which is the intended state until evidence exists.

### Exact share denominator

Denominator: every packet that passed selection in that window, meaning IPv4 TCP, UDP or ICMP addressed to the protected host, from every source and every protocol, including packets from allowlisted sources and non-first fragments. Not in the denominator: packets skipped by the normalizer or the frame filter (non-IP, IPv6, truncated header, bad length, unsupported protocol, not inbound, broadcast, multicast, VLAN). Numerator: the packets of that one `(src_ip, protocol)` group. This is `all_selected_packets` in the API contract. It is not the share within the matching protocol. Two consequences to review:

- A single-source flood has share 1.0 and a 10-source flood has about 0.1 each, so a high `min_share` deliberately leaves distributed or spoofed floods to the separate rate-limiting proposal.
- Because the denominator includes the legitimate client's traffic, the client's own share rises when it is the only source. The rate threshold, not the share, must keep it from qualifying.

### Method to set the numbers (no numbers invented)

Pick every value only from lab and validation runs, never from 03-11 or other final-test data. For each protocol:

1. Benign ceiling: the maximum per-window packets/s (and SYN/s for TCP) of any legitimate source across the benign validation runs.
2. Attack floor: the minimum per-window rate of a labelled attack source across the attack validation runs.
3. If the floor is not clearly above the ceiling, leave that protocol's threshold unset. Otherwise choose a value in the gap. The margin is a decision for Ayden and Ali, not something the current data decides.
4. `min_share`: pick from runs where the attacker and the client send at the same time. The value must keep the client's group below the rate threshold in every window and let the attacker through. Report how many validation windows change with each candidate value.

### Evidence to collect (proposed commands, run on the lab VMs)

Status 2026-11-11: the higher benign load, the SYN and UDP rate ladder, the mixed run, new-connection benign runs, benign UDP and ICMP, ICMP and multi-source attack runs, and separate repeated runs are done (tables in section 1). Still missing: the Week 2 baseline collection (`tools.collect_baseline`) and a larger or more varied benign population.

- Benign ceiling, several repetitions on `ddos-client`, with a server capture on `enp0s8`: the Week 2 baseline collector, then higher load on the same code.

```sh
./.venv/bin/python -m tools.collect_baseline --target http://10.10.10.10/ --rate 2 --duration 30 --repetitions 3 --timeout 5 --concurrency 1 --resource-record results/week2-resources.json --output results/week2-baseline
./.venv/bin/python -m ddos_detector.http_client --target http://10.10.10.10/ --timeout 5 --rate 20 --duration 60 --concurrency 4 --output results/benign-high
```

- Attack floor and ceiling: SYN and UDP scenarios at several rates (for example 50, 200, 1000 packets/s); the achieved rate is recorded in each run's `run.json`, so a rate the Python sender cannot reach is visible and is not assumed.
- Mixed run: the client's HTTP load and an attacker scenario at the same time, one capture.
- Each run needs its own capture file and its run ID, kept outside Git as in the Week 2 protocol; validation runs are whole runs, never neighbouring windows from one run.

## 3. Active block count, deduplication and reset rules

Defaults (recorded): 3 consecutive qualifying windows, 300 s timeout, `monitor_only` at startup. A window that is benign, empty, missing or capture-unavailable, or in which the group does not qualify, resets that group's streak to zero.

Proposed bookkeeping rules, for Ayden's review:

1. Streaks are kept per `(src_ip, protocol)`. A block is kept per `src_ip`: when an IP qualifies under several protocols there is still exactly one block entry, one cap slot and one 300 s timer, and its reason lists the first protocol that reached three windows.
2. The timer starts at the firewall's confirmed installation time of the first block and is never renewed by repeated detections or by another protocol.
3. Only firewall-confirmed blocks count as active. A pending request reserves one cap slot, so concurrent requests cannot exceed the cap. A definitively failed request with verified no installation releases the slot and records a structured failure. Timeout/unknown outcome keeps the reservation until reconciliation proves installed or absent; do not release an uncertain installation and exceed the cap.
4. Maximum active blocks: 20, configurable, a provisional lab value (agreed on #5). When it is reached, further eligible IPs get an `alert` with reason `block_cap_reached`, no existing block is evicted, and nothing is queued. When several IPs become eligible in one window, the heaviest group by packet count is served first, then lowest numeric IPv4 address for ties, so the result is deterministic.
5. Expiry is removal from the firewall confirmed by the adapter. Until it is confirmed the entry stays active and the slot stays used. After confirmed removal the IP's streaks are reset to zero, so a new block needs three new consecutive qualifying windows. (Alternative: keep the streak and re-block at once. This proposal chooses fresh evidence for every block; continued packet visibility during a block must be measured on the actual adapter/capture path, not inferred from the prediction stream.)
6. Switching `monitor_only` to `automatic` clears all streaks, so the first automatic block rests on three windows observed in automatic mode. Switching back does not remove existing blocks; they expire normally.
7. Never block: the protected server, loopback, and every allowlist entry (section 4). A qualifying allowlisted source yields `no_action` with reason `never_block`.

## 4. Lab interface and allowlist

Read from the running `ddos-server` on 2026-11-08 over SSH (read-only, no sudo; the VM was started for this and powered off again with its NAT link off, as before):

| Item | Value | Source |
| --- | --- | --- |
| Capture NIC | `enp0s8`, `10.10.10.10/24`, MAC 08:00:27:2c:42:76, link type Ethernet | `ip -br a`, `ip link show` |
| Management NIC | `enp0s3`, `10.0.2.15/24`, default route via `10.0.2.2`, DNS `10.0.2.3` | `ip route`, `resolvectl dns` |
| Management session | SSH peer address `10.0.2.2` (the NAT gateway) | `ss -tn` |
| Protected server | `10.10.10.10` | above |
| Legitimate client | `10.10.10.20`: source address of all HTTP client captures | pcaps |
| Attacker | `10.10.10.30`: source address of all scenario captures; never allowlisted | pcaps |
| Capture drops | 0 packets dropped by kernel in the `ctrlc-syn` capture | `ctrlc-syn.log` |

Proposed allowlist entries are in [policy-defaults.json](policy-defaults.json): 10.10.10.10, 10.10.10.20, 127.0.0.0/8, 10.0.2.2, 10.0.2.3 and 10.0.2.15. Management traffic is expected on `enp0s3`, but routing or forged source fields mean the adapter must not assume these addresses can never appear on the lab NIC. Apply allowlist checks before every action and scope enforcement to the verified lab interface/protected destination. The adapter must enforce both the allowlist check before any action and lab-interface/protected-destination scoping; it is not implemented yet.

`allowlist.verified` stays `false`. Enforcement must not be enabled with it: the runtime interface values above are observed, but the adapter's scope and allowlist handling are not implemented or tested.

Firewall and netplan state, reported by Vince from `ddos-server` on 2026-11-08 (with sudo; not independently reproduced):

| Item | Reported result |
| --- | --- |
| `ufw status verbose` | `Status: inactive` (the `ufw` service unit is enabled, but the firewall is off; an earlier note here that `ufw` was active was wrong) |
| `nft list ruleset` | empty |
| `iptables -S` | only the default policies: INPUT, FORWARD and OUTPUT all `ACCEPT`, no rules |
| netplan | `00-installer-config.yaml` (DHCP on `enp0s3`, matched by MAC), `60-lab.yaml` (`enp0s8` 10.10.10.10/24), `70-nat-routes.yaml` (`enp0s3` 10.0.2.15/24, default route via 10.0.2.2, DNS 10.0.2.3, DHCP off). The later file overrides the DHCP setting; the effective addresses and routes match the `ip` output above. |

So the server currently has no packet filtering at all. A block rule from the firewall adapter would be the first rule on the host, which means the adapter must create its own chain or table, scope its rules to `enp0s8` and destination 10.10.10.10, and never touch SSH on `enp0s3`. This is a requirement for Mujtaba's adapter, not something verified here. `nginx` is active (`systemctl is-active`), and `iptables` and `nft` are installed.

### Remaining questions for Vince

1. Is any machine other than the host PC and the two VMs meant to reach the server (a presentation laptop, for example)? If so its address belongs on the allowlist.
2. On the client and attacker VMs (ports 2223 and 2224): `ip -br a` should show `10.10.10.20/24` and `10.10.10.30/24` on `enp0s8`. I verified these only as packet sources in saved captures, not on the VMs.

## 5. Version-one scope

IPv4 TCP, UDP and ICMP only, inbound to the protected host. IPv6 is deferred until capture, address validation, API and firewall support are specified together. IPv6 frames are skipped and counted under `ipv6`, not scored, so an IPv6 flood would be invisible to this version. Source grouping, the share denominator and the block list are IPv4 only; the allowlist must hold IPv4 addresses or networks only.

ICMP: groups are built like TCP and UDP, but no ICMP flood evidence exists, so its threshold is unset (never qualifies) until ICMP runs are collected.

## 6. One window rule for offline and live

Both paths use the same `WindowAggregator` in `ddos_detector/aggregate.py`:

- Window index is `floor(ts / window_seconds)`, start is `index * window_seconds`, start inclusive and end exclusive, with timestamps in Unix epoch seconds. Timestamps 100.1 and 100.9 fall in [100, 101); 101.0 falls in [101, 102). A test in `tests/test_policy_defaults.py` pins this.
- Offline uses the PCAP record timestamp. Live prefers the kernel receive timestamp (`SO_TIMESTAMPNS`) and the current source falls back to `time.time()` at receive if ancillary timestamps are absent. Verify the actual timestamp source and clock alignment in lab evidence; do not claim kernel-timestamp coverage merely because the option was requested.
- A window is finalized once the newest timestamp or the live clock passes its end plus `grace_seconds` (1.0 s). Later packets for it are dropped and counted in `late_dropped`, so a finished window never changes. A decision for window `[t, t+1)` can therefore come about 1 s after `t+1`, plus inference time.
- Empty or missing intervals: the aggregator emits no record for a window without packets (`emit_empty=False`) and cannot know why. The policy consumer must treat every window index that is not exactly one `window_seconds` after the previous evaluated window as a streak break. This is the same for a measured empty interval and for unavailable capture; only reporting differs. A healthy capture with no packets is reported as zero traffic, while an unavailable capture is reported as unavailable (null rates), never as zero. Offline replays have no coverage information, so their gaps are reported as unknown and are never used as benign windows or as zero traffic. For scale: in the PR #29 candidate captures 62 of 541 seconds have no record.
- The policy consumer processes windows strictly in order and never re-evaluates a finalized window.

## 7. SYN/ACK features with inbound-only capture

Inbound-only capture never sees the server's SYN-ACK replies, because they leave the server. With the recorded formulas, `syn_ack_ratio` is the SYN-only count divided by `max(SYN+ACK count, 1)`, so whenever no SYN+ACK arrives inbound it equals `syn_count`. Measured on 2026-11-08:

- Lab captures: `syn_ack_ratio` equals `syn_count` in all 183 windows of the 8 PCAPs that produced windows (the ninth, a failed-path run, has none).
- CIC-DDoS2019 candidate windows (PR #29): equal in all 479 windows.

So under inbound-only capture the feature carried no information beyond `syn_count` in any observed window. It would differ only if SYN+ACK packets arrive inbound (reflection or backscatter), which neither dataset showed. `syn_no_ack_share` (SYN-only versus ACK-set packets) uses only inbound SYN and ACK packets, so it is not made redundant this way; its usefulness is not assessed here.

Proposal: keep the twelve version-one features unchanged for the first validation, as already decided, and do not change them silently. Report the redundancy with the validation results. If Ayden agrees that it is redundant, remove or redefine `syn_ack_ratio` in a new feature schema version with retraining and an update to [feature-contract.md](feature-contract.md) before any training, never in place.

## 8. Open items

| Item | Owner | Needed to close |
| --- | --- | --- |
| Threshold values and `min_share` | Vince, then Ayden | The lab data in section 1 shows overlap between benign and attack rates for every protocol, so no value is proposed. Needs a different signal (for example the SYN-only fraction) or a decision on the margin and on a benign load model |
| Block rules 3 to 6 above | Ayden / Mujtaba | Owner accepted with the November 8 clarifications below; implementation/interface tests remain |
| Allowlist scope in the firewall adapter (own chain/table, `enp0s8` and destination scoping) | Mujtaba, Vince | Adapter design and tests; the server's current firewall state is now reported (empty) |
| `allowlist.verified` | Vince, Ayden | Only after the above; until then enforcement stays off |
| Feature `syn_ack_ratio` decision | Ayden | Retain all twelve version-one features for the baseline; record redundancy and revisit only in a separately versioned, retrained validation experiment |
| Offline/live adapter parity and coverage evidence | Vince, Ali | Not provided by this proposal |


## Owner decisions â€” November 8

Ayden accepts the documented share denominator and bookkeeping design, including pending-slot reservations, no eviction, confirmed-removal expiry, fresh streaks after expiry and mode changes, no timer renewal, numeric-IP tie breaking and allowlist checks plus lab-interface scoping. Unknown installation/removal outcomes retain their cap reservation until verified reconciliation. Returning to monitor-only stops new automatic requests but does not silently claim existing blocks removed; confirmation and expiry still apply. This accepts a design, not working enforcement.

Keep `syn_ack_ratio` and all twelve schema-v1 features unchanged for the baseline. The reported redundancy is worth recording but does not justify silently changing a model contract. A later schema-v2 comparison requires new artifacts, validation-only selection and retraining; the final test must not drive this choice. Retain null rate/share thresholds and `allowlist.verified=false` until actual evidence supports them. No runtime component loads these draft defaults.
