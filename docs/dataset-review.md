# Independent dataset review

Owner: Ali. Latest review: November 6, 2026. [PR #29](https://github.com/aydsman/ML-DDoS-Detector/pull/29) now supplies a candidate SYN join and 479 window records. The [independent review and reproductions](reviews/issue-3-pr29-review.md) reconcile its arithmetic and identify two additional code defects. **Verdict: needs changes; raw-data verification and independent run/split approval remain blocked.** The November 4 evidence review below is retained as historical context; the candidate handoff has now arrived, while the original PCAP/CSV inputs remain unavailable here.

## November 4 evidence and continuing acceptance limits

| Evidence | What was checked | Result / limitation |
| --- | --- | --- |
| [Official dataset description](https://www.unb.ca/cic/datasets/ddos-2019.html) | PCAP/flow-CSV distinction and published schedule | The page describes raw packets and flow-level labels. Its readable text does not establish the schedule's timezone, UTC offset or calendar-date mapping. |
| [Download page](https://cicresearch.ca/CICDataset/CICDDoS2019/) | Read-only retrieval on November 4 | Returned a registration form and server-error message; direct archive links, sizes and publisher hashes were not verified through that retrieval. This does not establish that interactive access or existing downloads are unavailable. No new download or registration is needed to inspect Vince's existing files. |
| [Vince's November 3 PCAP report](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6617753926) | Five archive names, reported byte sizes and locally computed hashes; stated scan limits | Recorded in [the reported inventory](dataset-inventory-reported.json). These are collaborator-reported values, not independently recomputed checksums. A scan of the first 3,000 packets per piece is insufficient to certify complete window labels or coverage. |
| [Ayden's bounded handoff](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6621822689) | Required sample, uncertainty handling and split review | Inspection scripts, exact selected member hashes and a reproducible packet/flow/window join are still required. The reported files on Vince's PC were not available in this checkout. |
| [Training loader](../ddos_detector/training_data.py) | Existing checks for schema/order, counts, exclusions, epoch boundaries, duplicate windows and cross-split capture content | These check consistency of supplied claims. They cannot prove packet labels, timezone conversion, benign provenance or independent runs. A nonempty review reference is not an actual review. |
| [Independent feature verifier](../tools/verify_pcap_features.py) | Existing separate feature computation through tshark/scapy | Reuse it with the selected PCAP and verified victim filter. No real-data feature-parity result is claimed here. |
| [Label-contract tests](../tests/test_dataset_label_contract.py) | Exact 80% boundary, below-threshold cases, exclusion overrides and accounting | Synthetic software checks only. These do not supply a real labelled sample, prove split independence or authorize training. |

**Verdict:** issue #3 stays open. The provisional 01-12/03-11 split is not approved for training; packet labels, independently benign examples, timezone/victim evidence and whole-run independence are still unverified. DrDoS_UDP and UDP must be treated as potentially different reflection/flood scenarios until evidence establishes their relationship. Do not call them a matched benchmark by default.

## Handoff required from the existing files

Start with the reported SYN candidate suffixes `0618`–`0620` in `PCAP-01-12_0500-0749.zip` and a small explicitly named UDP selection, as requested in issue #3. The suffixes identify candidates to inspect; the full selected member names and member hashes must come from the actual archive. No additional bulk download is needed for this handoff.

Provide the existing enriched-window JSON and manifest format from [training.md](training.md#real-data-handoff-format), plus compact supporting evidence:

1. Exact archive/member paths, actual member byte sizes and SHA-256 hashes, CSV filenames/hashes, inspection-script commit, dependencies, commands and sampling limits. Record archive hashes separately from member hashes. Hash the real files after closing them.
2. Original packet/flow/schedule timestamps and the exact interpretation/conversion, with cited metadata and concrete matched examples. A four-hour shift that happens to align a burst is not verification. Leave unresolved interpretation unknown.
3. Stable capture/frame identifiers linked to original CSV row/flow identifiers and window IDs. Include protocol, both addresses/ports, direction, raw times and half-open interval bounds so Ali can repeat the join independently. Define handling of overlapping flows, unmatched/ambiguous packets, fragments and spoofed-source evidence.
4. Explicit evidence for every benign packet. Subtracting attack and unknown counts from total packets does not independently prove the remainder benign. Low traffic, a quiet interval or an apparent source address alone is insufficient.
5. SYN/UDP/benign scope and exclusions for MSSQL and other unsupported scenarios, including their associated packet windows. Dropping flow-CSV rows alone does not remove those packets from a PCAP. Retain an exclusion ledger/counts; never force out-of-scope traffic into benign. If the existing enriched schema cannot express a necessary exclusion, record the incompatibility for review rather than inventing flags/counts to make the loader accept it.
6. Whole-run identities and proposed train/validation/final-test membership, with evidence of independence. Different archive pieces or filenames from one run are not independent runs. State shortages of independent benign/SYN/UDP examples before proposing any revised split; keep final-test observations out of tuning.

The sample should include positive, independently benign, mixed, boundary and unknown/unmatched examples when supported by actual evidence. Mark unavailable cases as missing evidence, not fabricated examples. This handoff adds no new mandatory training schema or join algorithm before the actual data is inspected.

## Independent checks when the handoff arrives

- Recompute hashes for the supplied members and metadata; reconcile them with the manifest and retained source records.
- Repeat the join for a bounded selection of actual frame/flow IDs, including ambiguous, unmatched, fragmented and spoofed-source cases. Record discrepancies and unresolved labels explicitly.
- Independently verify each selected window's packet, attack, unknown and excluded counts, coverage and interval flags. Check the exact 8/10 threshold, 7/10 exclusion and benign-outside-attack rule against real evidence; a claimed 80% fraction is not enough when coverage, boundaries or labels are unknown.
- Run the existing independent feature comparison with the same verified victim/filter and epoch grid; retain output and investigate mismatches. Feature equality does not establish correct ground truth.
- Check declared run independence beyond unique filenames/hashes; verify no contiguous pieces of the same run cross train/validation/final-test boundaries. Record any permitted cross-scenario evaluation explicitly.
- Use the training loader's `prepare` command only after the evidence and review references are truthful and the manifest is ready. It requires eligible benign and attack rows in all three splits; an initial inspection sample need not meet that training requirement. Do not add dummy splits/rows or set synthetic data to `reviewed_packet_windows` to make it pass.
- Retain all inclusion/exclusion and coverage counts. Record a decision (`accepted`, `needs_changes` or `blocked`) with the exact reviewed commit, input/member/metadata hashes, commands/results, reviewer and unresolved items. Ayden reviews the resulting scope/split before real training.

For code checks, from the repository root:

```sh
./.venv/bin/python -m pytest -q tests/test_dataset_label_contract.py tests/test_training.py
```

For feature comparison once a real sample is available, use the existing verifier with a selected PCAP and verified victim address, for example `python -m tools.verify_pcap_features <selected-member> --engine scapy --victim <verified-victim-ip>`. Choose the engine deliberately and keep the command/output with the evidence. This command is not a packet-label or split-independence check.

The supplied candidate code/JSON has now been reviewed at the exact head recorded above. Raw-evidence verification, repaired-code re-review and split approval remain pending. Passing synthetic tests or reconciling candidate arithmetic is not a reason to close issue #3.
