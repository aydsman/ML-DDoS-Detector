# Week 2 saved packet fixtures

Owner: Ali. These are deterministic **synthetic software fixtures**, not captured lab traffic, a baseline service measurement, CIC-DDoS2019 data, or independent attack ground truth. They exercise the version-one packet/feature contract without a VM or network access.

The two small classic Ethernet PCAP files are stored in `tests/fixtures/week2/`. Only their exact filenames are exempted from the repository's PCAP ignore rule. `expected.json` contains literal normalized-packet and feature expectations, with source bytes and SHA-256 checksums fixed for review. Real captures remain excluded from Git.

## Reproduce and check

From the repository root with Python 3.12 and dependencies installed:

```sh
./.venv/bin/python -m pytest -q tests/test_week2_feature_fixtures.py
./.venv/bin/python -m tools.create_week2_fixtures --output /tmp/week2-fixtures-rebuilt
```

Use a fresh rebuild directory: the tool refuses to overwrite files. The tool uses only Python's standard library to build Ethernet/IP/transport and PCAP bytes; it imports no production extractor and never writes expected values. Tests compare rebuilt bytes with saved files/hashes, then compare the offline extractor and `LivePipeline` replay separately against the literal oracle. Idle clock ticks are also exercised. A shared implementation bug cannot pass merely because offline and replay outputs agree: both must match the independent expected numbers below.

The fixtures use integer microsecond timestamps, IPv4 Total Length (including headers, excluding Ethernet/padding), one-second epoch windows and the default uncapped source tracking. Expected decimals use a tolerance of `1e-12` relative/absolute. Every feature name and vector position is checked.

## Mixed protocols, epoch boundaries, and RST traffic

`synthetic-mixed-boundaries.pcap` contains 12 frames, nine selected inbound packets, two `not_inbound` skips and one `non_ip` skip. Let A = `10.10.10.30`, B = `10.10.10.31`, C = `10.10.10.32`, and victim = `10.10.10.10`.

| Epoch time | Source / destination | Contents | IP bytes / outcome |
| --- | --- | --- | --- |
| 100.100000 | A -> victim | TCP SYN | 60 |
| 100.200000 | B -> victim | TCP SYN+ACK | 100 |
| 100.300000 | A -> victim | UDP | 80 |
| 100.400000 | victim -> A | TCP SYN+ACK | 200; ignored outbound |
| 100.600000 | Ethernet ARP | Non-IP | ignored |
| 100.999999 | B -> victim | ICMP | 80; still in [100,101) |
| 101.000000 | A -> victim | TCP SYN | 60; belongs to [101,102) |
| 101.250000 | A -> victim | TCP RST, without ACK | 60 |
| 101.500000 | B -> victim | UDP | 60 |
| 101.750000 | C -> victim | UDP | 60 |
| 101.900000 | A -> 10.10.10.99 | TCP SYN | 40; ignored other destination |
| 103.000000 | A -> victim | ICMP | 28; Ethernet padding is excluded |

Hand calculations:

- **[100,101):** four selected packets, 320 IP bytes, sizes `[60,100,80,80]`. Mean = 320/4 = 80 bytes. Population variance = `(400 + 400 + 0 + 0)/4 = 200`; standard deviation = `sqrt(200) = 14.142135623730951`. One SYN-only, one SYN+ACK and one ACK-set packet give SYN count 1, SYN/ACK ratio `1/max(1,1) = 1`, and SYN-no-ACK share `1/(1+1) = 0.5`. Two packets from each source give two unique sources and entropy `-2*(0.5*log2(0.5)) = 1`. TCP/UDP/ICMP shares are 2/4, 1/4, 1/4. Rates are 4 packets/s and 320 bytes/s.
- **[101,102):** four 60-byte packets give 4 packets/s, 240 bytes/s, mean 60 and standard deviation 0. The inbound RST contributes to packet count, bytes, TCP share and source statistics. It adds neither SYN nor ACK to the SYN features: SYN count 1, SYN/ACK ratio 1, SYN-no-ACK share 1. Sources have counts `[2,1,1]`, so there are three sources and entropy `-(0.5*-1 + 0.25*-2 + 0.25*-2) = 1.5` bits. Protocol shares are TCP 0.5, UDP 0.5 and ICMP 0. This represents flag semantics only; it does not claim a real kernel generated the RST.
- **[103,104):** one 28-byte ICMP packet gives packet rate 1, byte rate/mean 28, size deviation 0, one source, entropy 0, ICMP share 1, all TCP/SYN/UDP features 0.

No packet is supplied for [102,103). The default aggregator emits no record there. That absence establishes neither a measured zero interval nor healthy capture coverage or a benign label. Replay completion is a software-processing check, not a completeness claim for a network capture.

## Fragmented and truncated TCP headers

`synthetic-fragments-truncation.pcap` contains six frames, four selected inbound packets, one `bad_length` skip and one `ipv6` skip.

| Epoch time | Source | Contents | IP bytes / expected flags |
| --- | --- | --- | --- |
| 200.100000 | A | First TCP fragment, MF set, offset 0 | 60 / SYN (2) |
| 200.200000 | A | Matching non-first TCP fragment, offset 5 in eight-byte units | 40 / unknown (`null`) |
| 200.300000 | B | TCP capture truncated after 20 IP + 10 TCP bytes | declared 100 / unknown (`null`) |
| 200.400000 | B | UDP | 40 / 0 |
| 200.500000 | A | Malformed IPv4 Total Length 10, smaller than its 20-byte header | skipped `bad_length` |
| 200.600000 | IPv6 | Unsupported address family | skipped `ipv6` |

The two fragments share an identification value and contain a split TCP segment. Features count IP packets separately without reassembly. The truncated record stores 44 captured bytes (14 Ethernet + 30 IP/transport) and original frame length 114; the usable IP header declares 100 IP bytes. Its absent TCP flags are not inferred from the uncaptured original data. A later fragment's payload bytes are not a transport header.

For [200,201), selected lengths `[60,40,100,40]` total 240 bytes, so packet rate = 4 and byte rate = 240. Mean = 60, variance = `(0 + 400 + 1600 + 400)/4 = 600`, and population standard deviation = `sqrt(600) = 24.49489742783178`. Two packets each from A/B give two unique sources and entropy 1. Three TCP packets and one UDP give shares 0.75/0.25/0. Only the first fragment has known TCP flags; SYN count = 1, SYN/ACK ratio = 1 and SYN-no-ACK share = 1. Unknown flags still contribute to packet, byte, source and protocol aggregates.

## Limits and remaining Week 2 evidence

Passing these tests verifies saved fixture parsing, normalization, all twelve feature values, epoch assignment, diagnostics and replay processing. It does not establish actual capture completeness, network clock synchronization, live socket/NIC behavior, dataset labels, detector accuracy, or service performance. Lab PCAPs and generator/client exports still require independent timestamps, run identities and coverage evidence. Native-machine results must not be labelled as a controlled VM baseline.
