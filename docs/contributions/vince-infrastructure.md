# Lab infrastructure and packet processing

Author: Vince. Draft reviewed November 26, 2026, for report sections 3 (architecture, capture side), 4 (lab and reproducibility) and 5 (dataset and features, capture side). It describes implemented components and the lab observations reported so far. Results that still need new recordings are marked as pending, and nothing here is an evaluation result.

## Isolated lab

The lab is three Ubuntu Server VMs on one Windows host running VirtualBox. Each VM has two network adapters:

| VM | Role | Lab address (`enp0s8`) |
| --- | --- | --- |
| `ddos-server` | Protected nginx web server, capture point, detector | 10.10.10.10/24 |
| `ddos-client` | Legitimate HTTP client | 10.10.10.20/24 |
| `ddos-attacker` | Controlled SYN/UDP traffic (hping3, project scenario runner) | 10.10.10.30/24 |

`enp0s8` is attached to the VirtualBox internal network `ddoslab`, which has no adapter on the host, so lab traffic can't reach the host or the internet. `enp0s3` is a NAT adapter used only for SSH from the host (forwarded ports 2222–2224) and for package installation. It is switched off before any flood. The NAT adapter is configured with a static address because the DHCP lease installed extra host routes that sent lab traffic out through NAT. The symptom was `ttl=61` replies and HTTP timeouts. Step-by-step build commands, clone fixes (machine ID, SSH host keys, netplan MAC pin) and the capture check are in [lab-setup.md](../lab-setup.md). The build was tested with VirtualBox 7.2.22 and Ubuntu Server 26.04.1.

The capture check sends 10 SYN packets from the attacker. The reported check on the server's `enp0s8` saw 30 frames: 10 SYNs, 10 SYN-ACKs and 10 RSTs, with 0 kernel drops. Actual totals depend on replies and retransmissions; this checks the capture point, not end-to-end loss.

**Environment record (rebuilt lab, November 25–26, 2026).** The original VMs and the raw captures stored with them were lost when the host PC was reset on November 21, 2026 (see issue #49). The lab was rebuilt from lab-setup.md on the same host. This doubles as a fresh-deployment reproducibility check. Earlier lab observations remain tied to the original VMs and their recorded revisions.

| Item | Rebuilt lab |
| --- | --- |
| Host | Windows 11 Home, 32 GB RAM, Hyper-V/VBS active (VirtualBox runs on the Hyper-V backend) |
| Hypervisor | VirtualBox 7.2.22r175245 |
| Guests (all three) | Ubuntu Server 26.04.1 LTS, kernel 7.0.0-44-generic, 2 vCPU, 2048 MB assigned, 15 GB disk (LVM, 9.8 GB root), clock UTC with NTP sync |
| Interfaces | `enp0s3` NAT 10.0.2.15/24 static; `enp0s8` on `ddoslab`: server 10.10.10.10, client 10.10.10.20, attacker 10.10.10.30 |
| Server tools | nginx 1.28.3, tcpdump 4.99.6 / libpcap 1.10.6 (TPACKET_V3) |
| Attacker tools | hping3 3.0.0-alpha-2 |
| Detector runtime (server) | Python 3.12.16 (installed with uv, since the system Python is 3.14.4), repository at `development` a2ea466; numpy 2.5.5, pandas 3.1.1, scikit-learn 1.9.1, joblib 1.6.0, scapy 2.8.0, fastapi 0.165.0, uvicorn 0.54.0 |
| Test suite on server | `pytest -q`: 587 passed, 7 skipped (as non-root; root-only capture tests skip) |
| Checks | client → server ping `ttl=64`, HTTP 200; 10-SYN capture test on `enp0s8`: 30 packets (SYN, SYN-ACK, RST for each), 0 dropped by kernel |

**Trusted model runtime.** The initial environment above used NumPy 2.5.5 and cannot load the existing trusted model under its compatibility guard. Restore and hash-check the restricted model handoff, then install its `model-requirements.txt` alongside the project requirements: NumPy 2.5.4, SciPy 1.18.1, scikit-learn 1.9.1 and joblib 1.6.0 on Python 3.12. The original model package survives; the lost raw captures do not. Later timing rehearsals in draft PR #54 used different host settings and must retain their own environment record. They are not general instructions to change teammates' host security settings.

One rebuild problem worth recording: after its post-clone reboot, the client once stopped answering on both adapters while its console stayed responsive. A VM reset fixed it, and the previous boot's log shows no errors. This may be a VirtualBox-on-Hyper-V stall and should be watched during long runs.

## Packet-processing pipeline

Offline pcaps and live capture share one code path, so a model trained on saved captures sees the same feature definitions at runtime:

1. **Frame source.** `pcap.py` reads classic Ethernet pcaps. `capture.py` reads frames from a Linux AF_PACKET socket (standard library only; requires root or CAP_NET_RAW) on the interface named with `--interface`.
2. **Frame parsing and selection.** `frames.py` parses Ethernet and IPv4 and keeps only inbound packets addressed to the protected server.
3. **Normalization.** `normalize.py` turns each IPv4 packet into the shared record (timestamp, source, protocol, size, TCP flags). Non-IP, IPv6, unsupported protocols and invalid or incomplete IPv4 headers are skipped and counted by reason. Packet size is the IPv4 Total Length, not the captured byte count, so payload truncation can preserve the size if the complete IPv4 header remains valid; invalid or incomplete headers are rejected. Non-first fragments count toward packet, byte, protocol and source totals, but their TCP flags are recorded as unknown rather than guessed.
4. **Windowing.** `aggregate.py` assigns packets to one-second windows aligned to Unix epoch seconds (start inclusive, end exclusive). A window closes when a packet or the clock passes its end plus a one-second grace period, so a quiet link still closes windows. State is bounded: at most 10,000 distinct sources are tracked per window. Beyond that the window is marked `capped`, and source-diversity features no longer describe all traffic. Capped windows are excluded from training and scoring. Size statistics come from a per-size histogram, so closing a window doesn't scale with its packet count.
5. **Features.** `features.py` computes the twelve version-one features in the fixed order of [feature-contract.md](../feature-contract.md).

`offline.py` and `live.py` are thin drivers around this path. `tests/test_live.py` checks that the same frames give identical records through both. `tools/verify_pcap_features.py` recomputes every window independently from tshark or Scapy output and compares the two. It agreed with the package on nine lab captures (PR #18).

**Measured silence versus missing data.** No record is written for a window without packets, because the aggregator can't tell a quiet link from a capture gap. If the frame source fails, the pipeline reports `unavailable`, discards windows with incomplete coverage and reports the gap. It never zero-fills. When capture stops, the window in progress is dropped rather than emitted half-measured.

## Monitor-only runtime and operation

`monitor.py` scores each finished window with a saved model package. It appends one JSON line per window to a new audit file (an existing file is refused) and never contacts a firewall. Each live window records `processing_delay_s`, the time from the window's end to the start of model scoring. Model scoring time is recorded separately as `scoring_s`; this is not full alert delivery latency. It is about 1.0 s with the grace period. The terminal status record reports skips, late-dropped packets, capture gaps and the maximum processing delay. The dashboard API can run the monitor in the same process and serve its state live (see [monitor.md](../monitor.md)).

Draft PR #41 adds start and stop scripts for the lab server:
- Start reports success only after the monitor writes its first status record.
- Start and stop share a lock, and a second start is refused.
- Stop signals a process only if its PID, start time and command line all match the state file.
- The management interface `enp0s3` is refused as a capture interface.

The same PR records the capture socket's kernel drop counters when they're available. These describe the monitor's own socket, not total path loss. The scripts passed a Linux recheck on `ddos-server` on November 20. An independent teammate reproduction is still pending.

## Lab observations to date (original lab, raw files outside Git)

- **Benign monitor run, November 11:** 100 s on `enp0s8` with a synthetic model. 225/225 HTTP requests succeeded, 72 windows were scored, 0 packets arrived late, and the maximum processing delay was 1.44 s. This checks the plumbing only.
- **Trained-model live runs, November 21 (issue #48):** three benign runs through the saved controlled-lab Random Forest and the live dashboard API. They scored 70, 57 and 46 windows, and every HTTP response was 200. Ayden's review reproduced all 46 run-03 scores from an independent tcpdump of the same run. This is an integration result, not an attack-accuracy result.
- **Policy evidence (docs/policy-proposal.md):** 61 server captures, all with 0 kernel drops. Benign and attack per-second rates overlapped: TCP SYN-only benign up to 454/s versus a lowest attack of 54/s, and UDP benign up to 2,356/s versus 54/s. No single rate threshold separates them, so the policy thresholds remain unset.
- **Controlled-lab sessions S1–S3 (November 12–13):** three ~15-minute captures with 0 tcpdump drops. Sent packet counts equal captured counts for every attack run. Windows were labelled from run logs with an 80% attack-share rule plus boundary exclusions, then split by whole session: train S1, validation S2, held-out test S3. The window records survive as the `lab-handoff.zip` attachment on issue #3. The raw captures were lost in the host reset, so per-source counts for the source-blocking policy (issue #49) must come from re-recorded sessions.

## Limitations

- **One host.** All three VMs share one physical machine and one hypervisor. Capture timing, achievable flood rate and drop behaviour reflect that host, and VirtualBox on a host with Windows' Hyper-V layer active may add scheduling jitter.
- **Inbound capture only.** The server's SYN-ACK replies are never observed, so `syn_ack_ratio` equals `syn_count` in every lab window measured (docs/policy-proposal.md, section 7). The feature was kept unchanged for version one by owner decision.
- **Capture completeness isn't proven.** tcpdump and socket counters report drops at their own capture point only. Upstream loss in the virtual network isn't measured.
- **Unreproducible evidence.** The pre-reset raw evidence can no longer be independently re-derived. Only the attached window records and reviews remain.
- **No public data.** No CIC-DDoS2019 data was accepted into training (issue #3), so nothing here supports claims about real-world traffic.

## Source and references

Code: `ddos_detector/pcap.py`, `capture.py`, `frames.py`, `normalize.py`, `aggregate.py`, `features.py`, `offline.py`, `live.py`, `monitor.py`; `tools/verify_pcap_features.py`. PRs #8, #18, #28, #31, #37, #38, #39 and #41. Documents: [lab-setup.md](../lab-setup.md), [monitor.md](../monitor.md), [feature-contract.md](../feature-contract.md) and [policy-proposal.md](../policy-proposal.md).
