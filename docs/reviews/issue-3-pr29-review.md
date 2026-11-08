# Ali's issue #3 candidate-data review

Reviewed November 6, 2026 (America/Toronto). Source: [PR #29](https://github.com/aydsman/ML-DDoS-Detector/pull/29), exact head `83e62f2ad99dd63f81a5a963183632786bae95e9`. Review verdict: **needs changes; dataset approval remains blocked by missing raw evidence and independent runs.** This completes the review of the supplied code/JSON at this head, not issue #3's real-data acceptance criteria.

The inspection utility from PR #27 and independent verifier fixes from PR #28 are now in `development` at `a1733e8`. PR #29 is a separate candidate join/sample. Its inputs remain on Vince's PC; no CSV/PCAP was downloaded, changed or used for training in this review.

## What was independently checked

[The saved audit](pr29-candidate-audit.json) records the actual candidate-file hashes, arithmetic, label decisions, feature consistency bounds, referenced run/capture identities and unchanged training-loader rejection. Its `raw_input_hashes_recomputed`, `ground_truth_independently_verified`, `feature_parity_independently_verified`, `timezone_verified` and `training_approved` fields are all false.

| Check | Result |
| --- | --- |
| Packet-count partition | 5,328,388 selected = 4,707,045 supplied attack-labelled + 621,343 unknown |
| Window decisions | 479 records: 8 candidate attack, 471 excluded, no independently benign windows |
| Unknown reason totals | 611,231 no-flow matches + 10,112 no-usable-five-tuple records = 621,343 |
| Boundary flags | Four supplied boundary flags, all excluded. Unknown takes precedence, so the exclusion-reason summary legitimately has no boundary-first count. Flags were counted, not verified against original capture edges. |
| Positive candidates | Eight have 100% supplied attack labels, no unknowns and no supplied boundary flag; all lie inside the reported interval. Their SYN packet fractions are 99.9328–100%; one includes ten UDP packets. A scenario label is not proof that every packet carries a TCP SYN flag. |
| Feature checks | All twelve names/order, finite values, packet-rate/count and byte-rate/mean identities, integer protocol counts, source/entropy bounds and strict-mode ICMP unknown accounting are consistent. These are internal constraints, not a raw-packet feature recomputation. |
| IDs and splits | Three distinct reported captures, one continuous run, no split and null review references. Pieces are not independent runs. |
| Training gate | The actual unmodified loader rejects `candidate_unreviewed_packet_windows` with `data_kind must be synthetic or reviewed_packet_windows`. No reference or split was fabricated to bypass it. |
| Timeline | The 479 nonempty rows span 541 seconds, leaving 62 seconds unrepresented across 34 gaps. Omitted rows establish neither measured silence nor capture loss. |

Default join logic conservatively leaves CSV BENIGN, out-of-scope MSSQL and conflicting labels unknown. No independent benign packet evidence was supplied. The optional ICMP-to-protocol-0 inference remains unapproved and should stay disabled: similarity between aggregate counts cannot establish packet-level identity. The four-hour CSV offset is collaborator-reported empirical evidence for these inputs, not an independently verified named timezone or official schedule conversion.

## New reproduced code findings

Both probes use synthetic, offline packet bytes and a tiny synthetic flow CSV. They do not invalidate the current sample by themselves; they identify inputs on which the join violates the intended contract.

### P2: exclude attack-interval boundaries before promoting windows

At `tools/cic_flow_join.py:259-272`, `edge` covers only piece/run edges. The computed `inside_attack_interval` does not prevent attack promotion. In a single capture spanning seconds 100–104, use a SYN interval `[101.2,102.2]` and matched packets at 101.2, 101.8 and 102.1. The tool emits:

| Window | Supplied attack packets | Actual output |
| --- | --- | --- |
| [101,102) | 2 | attack, boundary=false, inside_attack_interval=false |
| [102,103) | 1 | attack, boundary=false, inside_attack_interval=false |

Both cross a label-interval boundary and must be excluded under [the existing label decision order](../dataset-plan.md#label-decision-order), even when every observed packet matches an attack flow. Include the relevant interval transitions in boundary handling and add onset/ending-window regressions; preserve fully interior positives. Do not treat every individual flow start within an otherwise continuous attack interval as a new global scenario boundary.

### P2: preserve distinct source hashes when piece filenames collide

At `tools/cic_flow_join.py:296-300`, capture IDs and manifest keys use `os.path.basename`. Inputs `a/piece.pcap` and `b/piece.pcap` with different contents produce duplicate capture IDs, but the captures dictionary keeps only the second file's hash. An earlier window originating in the first file then resolves to the second file's provenance.

Reject duplicate capture IDs/basenames before generating records, or use collision-free stable IDs consistently in windows, runs and manifests. Add a two-directory/same-basename regression. The three committed sample filenames are distinct, so this probe does not assert a collision in those artifacts.

## Existing owner findings still pending

Ayden already requested fixes for [nanosecond-to-microsecond scaling](https://github.com/aydsman/ML-DDoS-Detector/pull/29#discussion_r4477000321) and [malformed IPv4 records contributing offset matches](https://github.com/aydsman/ML-DDoS-Detector/pull/29#discussion_r4477000328). They remain in the reviewed head. Ali's new findings above are additional; they do not replace the owner review. Candidate manifests must remain unreviewed while these issues and evidence gaps are unresolved.

## Reproduce the review

Obtain a checkout or archive of the exact PR head above through the existing authenticated repository. Keep that checkout separate from the latest development checkout. Set `review_snapshot` to it. The audit pins the candidate JSON and loader bytes; the probes pin the reviewed join and record the other imported source hashes. Changed pinned inputs require a new review.

From this branch's repository root, with Python 3.12/dependencies installed:

```sh
review_snapshot=/path/to/pr29-at-83e62f2
./.venv/bin/python tools/reviews/audit_pr29_candidate.py \
  --snapshot "$review_snapshot" --output results/pr29-candidate-audit.json
./.venv/bin/python tools/reviews/reproduce_pr29_label_findings.py \
  --snapshot "$review_snapshot" --output results/pr29-label-reproductions
```

Use fresh output paths. The audit reads the committed candidate JSON and invokes the unchanged loader; the reproduction script writes only generated test fixtures/results beneath its new output directory and sends no traffic. Saved audit timestamps and script hashes will change on a fresh run; the pinned input hashes and substantive counts should match. These scripts retain a specific review's evidence, not a general training-data approval service.

At the reviewed head, the existing join/label-contract/training tests passed: **75 tests**, using:

```sh
cd "$review_snapshot"
/path/to/project/.venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_cic_flow_join.py tests/test_dataset_label_contract.py tests/test_training.py
```

Passing those tests did not cover the two new probes. Fixes should receive regressions in Vince's PR and re-review at their actual new head.

## Remaining handoff and decision

- Vince: fix the four code findings across the two reviews, rerun affected candidate generation, and retain exact source hashes, commands and dispositions. Supply a bounded, traceable frame-to-CSV-row evidence selection, including raw/interpreted times, five-tuples, direction, ambiguous/unmatched, fragment, boundary and out-of-scope cases. Actual raw inputs or independently inspectable slices are needed to verify their bytes and join results.
- Vince/Ali: retain capture coverage and gap evidence, independently benign examples, a named UDP selection and evidence of independent whole runs. Do not allocate the three pieces of this single run across training/validation/final testing.
- Ali: recheck the repaired code and independently reproduce the raw join/feature values when the evidence is accessible. Record actual source identities and conversion uncertainty; do not promote candidates just because the JSON arithmetic agrees.
- Ayden: decide the final scope/split after those checks. If the dataset cannot supply independent benign/SYN/UDP runs, review an explicit revised proposal; do not invent examples or silently replace the public-data experiment.

Issue #3 remains open. The candidate provides one run with no independently verified benign examples, named UDP selection or reviewed whole-run splits. The pilot plan caps eligible windows at 300 per class/split; that cap does not resolve these missing prerequisites. No model was trained and no benchmark or lab-baseline completion is claimed.
