# CIC-DDoS2019 SYN pieces 0618-0620: flow-label join (issue #3)

Status: candidate evidence for Ayden's and Ali's review. **Not reviewed, not usable for training.** It follows steps 2-4 of Ayden's issue #3 handoff for the SYN candidate only. Nothing here labels benign traffic, assigns a split or claims accuracy.

Inputs (kept outside Git, on Vince's PC): `Syn.csv` from `CSV-01-12.zip`, and pieces `SAT-01-12-2018_0618`, `_0619`, `_0620` from `PCAP-01-12_0500-0749.zip`. Piece and CSV SHA-256 values are in [`samples/cic-syn-0618-0620/manifest.json`](samples/cic-syn-0618-0620/manifest.json); the inspector from PR #27 gives the per-piece inventory.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m tools.cic_flow_join --csv C:\Users\iamno\datasets\cic-ddos2019\CSV-01-12\01-12\Syn.csv `
  --pieces C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0618 `
           C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0619 `
           C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0620 `
  --victim 192.168.50.1 --attack-label Syn --offset-hours 4 --run-id cic-2018-12-01-syn-a --out-dir results\cic-syn-0618-0620
```

About 90 seconds, read-only on inputs, refuses to overwrite `--out-dir`. Add `--icmp-as-protocol0` for the optional ICMP rule below.

## Timestamp offset: measured, not assumed

The CSV times are exactly 4 hours behind the PCAP epoch times. The tool tests every whole-hour offset from -6 to +6 and counts CSV flow starts that equal a packet with the same protocol, both addresses and both ports at the same microsecond:

| Offset (CSV + h = PCAP) | Flow starts matching a packet exactly |
| --- | --- |
| +4 h | 1,582,330 of 1,582,681 (99.98%) |
| every other hour, -6 to +6 | 0 |

Concrete example: the first CSV row (`172.16.0.5:53058 -> 192.168.50.1:53058`, TCP) starts `2018-12-01 13:30:30.741451`; the first packet in piece 0618 is at `2018-12-01T17:30:30.741451Z`. This resolves the 13:29 vs 17:30 discrepancy for this capture as a constant 4-hour CSV offset; it does not say which real time zone produced it, and the official timetable's day labels are not used. The offset has been checked only for `Syn.csv` and these three pieces. Re-test it per CSV/piece pair before reusing it (UDP and the 03-11 collection are untested).

## Packet labelling rule

An in-scope packet is IPv4, addressed to the victim, with a valid header and Total Length (same scope as the extractor), TCP, UDP or ICMP. It is matched to a CSV flow by 5-tuple, in either flow direction, and by the flow's `[start, start + Flow Duration]` interval at the offset above.

* `attack`: matched only to flows labelled `Syn`.
* `unknown`: no matching flow interval, labels that disagree, no usable 5-tuple (ICMP, non-first fragments), or a CSV `BENIGN` flow (the CSV label alone is not independent benign evidence).

The loader excludes a window that contains any unknown packet, so `unknown` is deliberately conservative. Features come from the package's own extractor over the three pieces in order, and each window's independent packet count must equal the extractor's (all 479 do).

## Result (default, strict)

| | Count |
| --- | --- |
| In-scope packets | 5,328,388 |
| Matched to `Syn` flows | 4,707,045 |
| Unknown: no flow interval | 611,231 (almost all in the 5 minutes after the CSV ends at 17:34:27 UTC, plus a few unmatched TCP) |
| Unknown: no 5-tuple | 10,112 (ICMP and non-first UDP fragments from 172.16.0.5) |
| Windows | 479: 8 `attack`, 471 `excluded` |

With `--icmp-as-protocol0` (an inference, off by default): ICMP packets are matched to the CSV rows whose Protocol is 0 (ports 0/0). Support: the three attacker-to-victim Protocol-0 rows record 8,840 forward packets against 9,966 ICMP packets from the attacker in these pieces, with start times within 10 ms of the first ICMP. The counts are close but not equal, so this is not proof. Result: 169 `attack`, 310 `excluded` (146 remaining unknown packets are non-first fragments). Treat those 169 as dependent on the inference until Ali confirms it.

## What is and is not available

| Case | Status |
| --- | --- |
| Positive (attack) windows | Available (8 strict, 169 with the ICMP inference) |
| Unknown / unmatched | Available: the whole 17:34:27-17:39:30 UTC tail of piece 0620 is outside the CSV and is **not** benign |
| Boundary windows | Available (piece edges and first/last second) |
| Mixed windows | Few: the packet-level mix inside the attack interval is the unknown ICMP/fragments, below 0.2% |
| Independently verified benign windows | **Unavailable.** `Syn.csv` has 392 `BENIGN` rows, none addressed to the victim, and the pieces contain no other victim-bound traffic with independent labels |
| Independent runs / split | **Unavailable.** All three pieces are one continuous run, so no train/validation/test assignment is possible from them |

Shortage to bring to Ayden: SYN positives exist from this one run; benign and UDP windows must come from other pieces and runs. A revised proposal needs a search of the 03-11 and other 01-12 pieces for independent quiet or benign periods, and a UDP selection, before any split.

## Files

`samples/cic-syn-0618-0620/` holds the default-run outputs: `windows.json` (479 enriched windows in the `docs/training.md` fields), `manifest.json` and `coverage.json`. The manifest uses `data_kind: candidate_unreviewed_packet_windows` on purpose, with null review references and an unassigned split, so the real loader rejects it and nobody trains on it by accident.

Loader check: with the kind and review references filled in a scratch copy, every per-window rule in `ddos_detector.training_data` passes and the only failure is the expected one, `train needs eligible benign and attack examples`.
