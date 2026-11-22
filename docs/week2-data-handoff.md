# CIC input handoff after the local join repairs

**Current status (November 18):** this file preserves the November 7 CIC reproduction instructions and historical training checkpoint. The current CIC decision and smaller next handoff are in [cic-acceptance-handoff.md](cic-acceptance-handoff.md). The separately approved lab pilot and its trained baseline are recorded in [PR #42](https://github.com/aydsman/ML-DDoS-Detector/pull/42); the historical W2 blockers below describe the CIC path and do not revoke that acceptance.

Owner of training/evaluation: Ayden. Source-file access and original capture evidence: Vince. Independent label/feature review: Ali. Status on November 7, 2026: **training is blocked by data/evidence; synthetic code verification is available.**

## Prepared locally

- Offline feature extraction and Random Forest training/evaluation pipeline are merged through PR #19. No real-data model or accuracy result has been produced.
- Baseline collection/review tools and independent synthetic feature fixtures are merged through PR #25. Actual VM baseline evidence remains a separate Ali/Vince deliverable.
- The four PR #29 join defects are repaired in tool version 2, with offline regressions. Ask Ali and Vince to review the actual repaired head; earlier approvals/findings apply only to their pinned source.
- Existing candidate manifests remain `candidate_unreviewed_packet_windows`, with null reviews and split. The loader continues rejecting them. Do not fill those fields with placeholders.
- The version-1 SYN sample and historical audit are retained unchanged. Their eight candidate positives and other counts must not be described as newly regenerated evidence.

## What can unblock real W2 training

1. **Access to selected inputs.** Vince can run the repaired tool on his PC, or share a bounded set of PCAP pieces plus the relevant original CSV and metadata outside Git. Start with `SAT-01-12-2018_0618`, `_0619`, `_0620` and the corresponding `Syn.csv` for reproduction. Supply exact filenames, sizes and full SHA-256 hashes, source/archive identity and time ranges. Do not transfer all archives unnecessarily. Any smaller slices need traceable selection commands, original identities, retained timing and appropriate boundary exclusions.
2. **Fresh candidate generation.** Run version 2 into a new output directory; retain its version/commit, exact command, hashes, raw/interpreted timestamps and output. The empirical +4-hour offset applies only after the corrected offset check supports it for those particular inputs; it is not a verified timezone or a blanket UDP/test-day conversion. Keep `--icmp-as-protocol0` off unless independently justified. Never infer benign from quiet or unmatched traffic.
3. **Independent inspectable evidence.** Ali needs access to original inputs or traceable slices to reproduce frame-to-flow matching and window features. Retain frame/row references, both addresses/ports, protocol, direction, times and label reasons. Include ambiguous, unmatched, fragment, truncation, boundary and out-of-scope cases where present. Reconcile counts and coverage; internally consistent JSON is insufficient. Record actual review evidence, not just a reviewer name.
4. **Missing classes and independent groups.** Supply a named UDP selection and independently supported benign windows, plus usable SYN examples. The three existing SYN pieces are one run, not three independent runs. Propose whole independent capture/run assignments for training, validation and final testing. Distinguish DrDoS_UDP from UDP flood; exclude MSSQL/other out-of-scope traffic. Keep final test data untouched by tuning.
5. **Ayden's acceptance and training.** After Ali's independent checks and the whole-run proposal, Ayden approves the scope/split, then prepares the reviewed manifest and runs the existing training/evaluation commands in `docs/training.md`. Report actual metrics and exclusions. If independent groups/classes cannot be obtained, bring back a concrete revised experiment proposal for Ayden; do not silently switch to lab-only data or split adjacent chunks as independent runs.

## Version-2 reproduction on Vince's existing inputs

After checking out the reviewed repaired head and installing the project's requirements, run from that repository root (replace input paths if necessary):

```powershell
python -m tools.cic_flow_join `
  --csv 'C:\Users\iamno\datasets\cic-ddos2019\CSV-01-12\01-12\Syn.csv' `
  --pieces 'C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0618' `
           'C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0619' `
           'C:\Users\iamno\datasets\cic-ddos2019\pcaps\x-01-12_0500-0749\SAT-01-12-2018_0620' `
  --victim 192.168.50.1 --attack-label Syn --offset-hours 4 `
  --run-id cic-2018-12-01-syn-a --out-dir results/cic-syn-0618-0620-v2
```

Use a genuinely fresh output path. Retain `windows.json`, `manifest.json` and `coverage.json`, plus raw-source identities and review evidence. Do not change the generated manifest to reviewed or allocate this one run across splits. This command checks the existing SYN candidate; it cannot create missing benign/UDP data or independent runs.

The detailed feature/label input format and final training commands remain in [training.md](training.md); the original candidate method and limitations are in [cic-syn-join.md](cic-syn-join.md). Keep [issue #3](https://github.com/aydsman/ML-DDoS-Detector/issues/3) open until its real acceptance evidence is met.

Current inspection/sourcing decisions: [November 8 dataset next steps](dataset-next-steps.md).
