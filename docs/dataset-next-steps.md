# Dataset decisions and remaining W2 evidence

These are Ayden's project decisions following Vince's [new collection findings](https://github.com/aydsman/ML-DDoS-Detector/issues/3#issuecomment-6725846803). They authorize bounded inspection and preparation, not reviewed labels, a final split or model performance claims.

## Second SYN collection

Keep `SAT-03-11-2018_0143` and `_0144` as one candidate held-out collection/run group, using the reported victim `192.168.50.4`. Its reported 3,118 positive candidates are enough to warrant review; a thin subset is not automatically invalid. Preserve the reported +3-hour empirical conversion for these exact inputs only, pending raw matching checks. The +4-hour first-collection offset must not be reused.

The filename/day or a different victim alone does not establish independent runs. Verify original capture/scenario identities and overlapping content, record limitations, and exclude truncated `_0145`. Do not split `_0143` and `_0144` between training and validation. Reserve this collection as a provisional final-test candidate: raw label/feature validation is allowed, model/threshold tuning on its outcomes is not. The existing first collection plus this second collection still do not supply three independent train/validation/test groups or both required classes.

## UDP choice

Proceed with a **small, named `01-12/DrDoS_UDP` candidate selection from the already downloaded files**, with reproducible flow-to-packet matching and a fresh offset test. It is acceptable to investigate that explicitly named dataset UDP scenario within the binary SYN/UDP experiment. Do not rename it plain UDP flood or claim matched same-scenario generalization against `03-11/UDP.csv`. The isolated-lab plain UDP scenario remains a separate evaluation condition. Exclude MSSQL and other out-of-scope traffic rather than relabelling it benign.

One unsuccessful piece does not establish absence of UDP in all 146 pieces. A bounded metadata/index search of existing files is reasonable; do not start another bulk download or claim the public-data UDP benchmark complete. The [official dataset description](https://www.unb.ca/cic/datasets/ddos-2019.html) distinguishes attack families and supplies flow labels; exact scenario semantics and timestamp mapping still need verification on selected bytes.

## Benign evidence

First look for original BENIGN flow rows whose packet matches can be reproduced across a complete selected inbound window, with verified scenario/interval context. CSV labels alone, a quiet rate, an apparent legitimate source, unmatched packets or a gap in the supplied rows are not enough. Account for every selected packet, conflicting/overlapping flow matches, unknowns and capture completeness before a reviewer can certify a benign window. Preserve unknown labels and all exclusions.

In parallel, prepare a separately identified **controlled-lab pilot proposal** if the public data cannot supply the needed classes/groups. It should collect legitimate HTTP, bounded SYN and bounded UDP conditions in each of at least three independently started sessions, with whole sessions assigned to train/validation/final test before tuning. Use existing isolated-lab tools only. Retain generator run UUIDs/start-stop records, original server captures/hashes, service logs, actual client/server resources, verified target/interface, clock alignment and capture-drop/coverage evidence. Verify all selected background packets or exclude unknown windows.

Do not make a classifier from public attacks versus only lab benign traffic: it could learn differences between collection environments. A lab pilot needs benign and attack traffic from that lab and must be reported separately from the public-data experiment. This preparation is not a silent replacement of CIC-DDoS2019 or approval to mark W2 complete. Bring the actual class/run inventory and proposed split back for Ayden's final acceptance.

## November 11 decision for the Week 2 pilot

Vince reports zero verified benign windows and two independent SYN runs among the CIC captures he checked. Proceed with a separate lab pilot by reviewing existing captures and their logs offline. The CIC candidates remain a separate dataset investigation. The pilot is pending an inspectable set of lab inputs.

- Identify three independently documented lab sessions. Assign one whole session to training, one to validation and one to final test before window selection. Each split needs verified benign examples and examples from the intended SYN and UDP scope. If the available records cannot support that split, document the shortage and keep training pending.
- For each session retain capture names and SHA-256 hashes, capture coverage and timing evidence, and the corresponding service and run records. Reconcile those records against the captured traffic before applying labels. Mark unsupported windows excluded and keep the exclusion counts.
- Apply the existing [window label and feature contract](training.md#real-data-handoff-format), including its provisional 80% attack-packet rule. Use at most 300 eligible windows per binary class per split for this pilot. Fix a deterministic selection rule before training and record the retained and excluded counts by traffic type. Keep the final test out of model and threshold selection.
- Vince supplies the capture inventory and a small traceable window sample. Ayden can independently reproduce the sample's labels and features from the supplied inputs, then review the full split before training. Save the reviewed manifest with the inputs used for the run.

## CIC evidence handoff

Vince supplies fresh version-2 JSON outputs and raw/sliced PCAP/CSV evidence as specified in the owner recheck on PR #29. Ayden may perform the label/feature review; it does not depend on Ali personally. The reviewer must record actual checks. Acknowledged rerun totals are collaborator-reported until the files can be inspected. Keep candidate manifests unreviewed, issue #3 open, and final test outcomes out of tuning.
