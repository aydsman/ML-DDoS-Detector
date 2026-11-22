# Issue #3: CIC selection decision and next evidence

Checkpoint: November 18, 2026. Decision owner/reviewer: Ayden. Original-file access and next handoff: Vince. Ali may independently review the supplied packet/flow evidence; Ayden can take over that review.

**Decision: CIC training acceptance remains blocked by missing source evidence.** The agreed labels, features and split rules remain in effect. No new scope choice is needed from Ayden before that handoff. The separately approved controlled-lab pilot is recorded in [Ayden's acceptance](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6987025978) and [PR #42](https://github.com/aydsman/ML-DDoS-Detector/pull/42); CIC approval is not a prerequisite for that pilot. This checkpoint does not evaluate the lab's held-out S3 data.

## What Ayden checked now

- Read the full issue, PR #29's version-2 rerun report, the merged selection/label rules and the current candidate files. [The current artifact check](reviews/issue3-cic-status-2026-11-18.json) identifies the exact Git-blob SHA-256 values.
- The three committed candidate JSON files are unchanged from the historical PR #29 review. They still identify **tool version 1**, 479 windows, eight candidate attack windows and 471 exclusions. Supplied packet totals reconcile: 5,328,388 = 4,707,045 attack-labelled + 621,343 unknown. There are three captures from one run, no benign windows, no splits and null review references. These are checks of supplied records, not a fresh packet-label review.
- The current, unmodified training loader rejects those inputs with `data_kind must be synthetic or reviewed_packet_windows`. No manifest was promoted and no CIC model was trained. The 107 existing join, inspection, label-contract and training tests passed.
- Re-read the [UNB dataset description](https://www.unb.ca/cic/datasets/ddos-2019.html) on November 18. It distinguishes raw packets from labelled flows and lists server addresses `192.168.50.1` and `192.168.50.4` for its two days. That supports the published server inventory, not the correctness of any specific packet label or collection-to-day mapping. The page does not resolve the CSV timestamp interpretation. Read-only access to the [download endpoint](https://cicresearch.ca/CICDataset/CICDDoS2019/) returned a form/server error, not inspectable archives. This does not invalidate Vince's existing downloads.

## Exact bounded selection

These are **inspection inputs, not approved training inputs or split assignments**. Keep SYN, the explicitly named dataset UDP scenario and independently supported benign traffic in scope. Keep MSSQL and other attack scenarios out.

| Selection | Exact member / metadata | Current evidence and next action |
| --- | --- | --- |
| First SYN candidate | `SAT-01-12-2018_0618`, `_0619`, `_0620`; `01-12/Syn.csv` | One continuous run. The committed JSON is historical v1. Vince [reported a v2 rerun](https://github.com/aydsman/ML-DDoS-Detector/pull/29#issuecomment-6725563955); share the actual three v2 JSON outputs and bounded source evidence. The reported +4-hour conversion applies only to these inputs. |
| Second SYN candidate | `SAT-03-11-2018_0143`, `_0144`; `03-11/Syn.csv` | Vince [reported](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6725846803) +3 hours and 3,118 positive candidates. Output and source evidence are unavailable here. Keep this collection reserved from model/threshold tuning. Exclude truncated `_0145`. Different filenames do not prove independent runs. |
| First UDP inspection | `SAT-01-12-2018_0750` from `PCAP-01-12_0750-0818.zip`; `01-12/DrDoS_UDP.csv` | Ayden selects **one member** from Vince's reported UDP-dominant range for a first inspection. Confirm the actual archive path/member, size and hash first. Its hash, CSV matching and offset remain unknown. Do not assume this is plain UDP flood or a matched benchmark against `03-11/UDP.csv`. |
| Benign | Complete windows with traceable BENIGN-flow and packet/context evidence | No CIC benign window has been independently accepted. Quiet traffic, an apparent legitimate IP and unmatched packets do not establish benign labels. If none can be supported, report the shortage. Do not import only lab benign traffic to pair with public attacks. |

All existing SYN member hashes and the newer collaborator reports are indexed in [the reported inventory](dataset-inventory-reported.json). A reported hash is not an independently verified input. Direct archive URLs remain unverified; use the already downloaded files under Vince's reported `C:\Users\iamno\datasets\cic-ddos2019\` rather than downloading all archives again. The source page is not an archive URL.

## Small next handoff from Vince

1. **Share the existing v2 SYN outputs first.** Provide `windows.json`, `manifest.json` and `coverage.json` for each reported rerun, generated in a new directory. Retain tool commit/version, Python version, exact command, input paths/sizes/hashes, and actual output-file hashes. Leave kind, review references and split unapproved. Counts in a comment are insufficient to compare individual windows.
2. **Supply enough source evidence to reproduce a small selection.** Start with the first collection's positive window `cic-2018-12-01-syn-a-1543685431` and boundary/unknown window `cic-2018-12-01-syn-a-1543685430`, plus actual mixed/unmatched examples where available. Include original frame indices, raw timestamps, both addresses/ports/protocol/direction, matching original CSV row IDs/times/durations/labels, and every overlapping or conflicting flow. Include every selected inbound packet in each reviewed window. Do not filter away unknown, fragment or out-of-scope packets just to improve labels. Any PCAP/CSV slices stay outside Git and need their own hashes, original-parent hashes, exact extraction commands and retained interval margins. Context must support coverage and boundary decisions; two selected packets are not a complete window.
3. **Inspect the single UDP member.** With the existing file present, activate Python 3.12 and the project's environment, then use the command below. A 3,000-packet scan is only a bounded first look; a complete-window label or feature decision needs the full relevant interval. Match the original `DrDoS_UDP.csv` rows with a fresh offset comparison and concrete frame/flow examples before running a candidate join. Do not copy the SYN +4-hour setting or infer an offset by making a burst align. Report no-match/ambiguous cases honestly.
4. **Report the class/run shortage and an evidence-based proposal.** A complete CIC training experiment still needs reviewed benign and attack windows in independent train, validation and final-test groups. The two SYN collections do not supply three splits, and adjacent pieces cannot be divided to manufacture independence. Preserve the 300 eligible windows per binary class per split cap and the deterministic selection rule; keep all exclusions. If the source cannot support that experiment, bring back a concrete revised CIC evaluation proposal before training. The existing lab pilot remains separately identified.

Example bounded UDP inspection from the repository root, using Vince's reported extraction-directory convention (verify the actual path first):

```powershell
python -m tools.inspect_cic_pcap `
  'C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0750-0818\SAT-01-12-2018_0750' `
  --victim 192.168.50.1 --max-packets 3000 `
  --out results/cic-udp-0750-inspection.json
```

Use a new output path and create its parent directory first. The default full-file hash reads the whole member even though parsing stops after 3,000 packets. The victim option scopes only the inspector's `*_to_victim` counters: global protocol/rate summaries are not proof of victim traffic or continuous coverage. Review the report's scope notes. The detailed existing [v2 SYN reproduction command](week2-data-handoff.md#version-2-reproduction-on-vinces-existing-inputs) remains valid for its exact inputs.

## Acceptance after the handoff

Ayden or Ali must independently reproduce the supplied source hashes, selected packet/flow matches, full-window counts, labels, all twelve features, coverage/boundary decisions and whole-run split evidence. Preserve the established decision order: unavailable/capped/unknown/boundary/empty windows are excluded; a trustworthy nonboundary attack window needs at least 80% attack-labelled selected packets; benign needs independently benign packets, no unknowns and no attack interval. The 80% label rule is separate from the 0.5 experimental model-score threshold. Keep non-first fragment flags unknown and IPv4 Total Length bytes consistent with live extraction.

**Close #3 only after its actual CIC inventory, inspectable labelled sample, exclusions and defensible split requirements are met or the owner explicitly approves a revised issue scope.** Code tests, a repaired join, the approved lab pilot and this documentation do not satisfy those missing CIC requirements.
