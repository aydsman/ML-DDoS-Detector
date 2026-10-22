# Design decisions: dataset, window, features

## Dataset (hybrid)
- **Offline training:** subset of CIC-DDoS2019, using the raw pcaps (not the CICFlowMeter CSVs). Attack types: SYN, UDP, and optionally DNS or NTP, plus benign traffic. Stored under `data/` (gitignored).
- **Live validation:** traffic generated on the Linux VMs. Attacks via hping3 (SYN flood, UDP flood); benign via a normal web workload. Labels come from recorded attack start/end times.
- Both sources go through the same feature extractor, so training and live capture cannot drift apart.

## Window
- Default 1 second, non-overlapping, configurable (try 1s, 2s, 5s later).
- A window is labelled attack if it overlaps a recorded attack interval, otherwise benign.

## Feature list (shared by offline and live)
| Feature | Notes |
|---|---|
| packet_rate, byte_rate | per window |
| syn_count, syn_ack_ratio, syn_no_ack_share | TCP flags |
| pkt_size_mean, pkt_size_std | payload size |
| unique_src_ips, src_ip_entropy | source diversity |
| tcp_share, udp_share, icmp_share | protocol mix |

## Leakage rules
- Drop raw IPs, ports, flow IDs, timestamps as features.
- Split train/test by attack type or by time, never randomly across windows.
- Fit any scaling on the training split only.

## Open items
- Branch strategy (suggested: main plus short-lived feature branches).
- Exact CIC-DDoS2019 pcap files to download.
