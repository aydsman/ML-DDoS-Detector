# Presentation outline and rehearsal checklist

Prepared November 26, 2026 for Ayden's Week 6 technical review. Five-minute outline using existing functionality. No final results, live incident test, recording or actual team rehearsal is claimed.

## Before the demo

- Select and record the exact tested development commit. Match each report/figure to its evidence revision; current code and historical lab runs have different dates.
- If the existing dashboard preview is running, check its Data source and warning before presenting it. API data is not automatically live: an archived audit or replay is historical.
- For an empty local API plus the existing sample selector, run `python -m uvicorn ddos_detector.api:app --host 127.0.0.1 --port 8006` in the project Python 3.12 environment. Open `http://127.0.0.1:8006/frontend/`. This starts no capture, scoring or firewall activity. Select sample data for the fabricated-data tour; the empty API must remain visibly unavailable.
- To show an accepted archived monitor run, use the existing `python -m ddos_detector.api --audit-log PATH_TO_COMPLETE_RUN.jsonl --port 8006` procedure in [monitor.md](monitor.md). Use the actual retained complete audit file and keep its historical label. Do not overwrite a running preview's port.
- Check sidebar expansion, all four pages, graph inspection and a narrow layout. Test visible keyboard focus. For reduced motion, demonstrate correct final values without requiring animation.
- Prepare a fallback using the verified benign-service figure and source tables in [Ali's contribution](contributions/ali-evaluation.md). Identify screenshots/sample values as such; they are not a live demo or an active firewall result.

## Five-minute talk track

| Time | Show / explain | Evidence boundary |
| --- | --- | --- |
| 0:00-0:30 | Problem and scope: detect suspicious aggregate inbound SYN/UDP lab traffic and display evidence. | This is a controlled-lab project, not a claim that a server is universally safe. |
| 0:30-1:15 | Packet selection -> one-second aggregation -> 12-feature guard -> saved model -> bounded API -> dashboard. Separate source policy and confirmed firewall actions. | The classifier does not prove which IP is malicious or identify the attack type. Automatic policy integration is still pending. |
| 1:15-2:00 | Overview: health, data-source mode, freshness warning, packet rate and byte rate. Expand/collapse navigation. | Say whether this is sample, recorded, unavailable or current lab capture. A recent HTTP response does not make an old measurement current. |
| 2:00-2:35 | Traffic: inspect an actual plotted reading with timestamp and units; explain missing-data gaps and latest values. | Samples are fabricated. Lines/entrance animations add no measurements; missing is not zero. |
| 2:35-3:10 | Detections and Blocks: scores/thresholds, evidence, source diagnostics where present and action records. | A detection is not a block. Historical confirmed records do not establish current protection. Status indicators are informational. Do not promise unimplemented controls. |
| 3:10-4:15 | S1/S2 split method, forest/MLP/rate-rule comparison and inference timing. | S2: forest and MLP 300 TN/250 TP/zero errors; rule 296 TN/4 FP/250 TP/0 FN. These are validation outcomes on one narrow session. The MLP was faster on the laptop; prediction cost excludes capture/API/firewall time. S3 is unscored. |
| 4:15-5:00 | Accepted benign live integration, limitations and remaining work. | Run 03 reproduced 46 packet-derived scores/204 selected packets and 34 distinct byte-rate windows. This checks integration, not attack accuracy. Original raw captures were lost; new policy sessions are separate. Explain pending policy/lab/final-evaluation evidence. |

## Questions to practise

- Why Random Forest as the current integration candidate? The existing trusted/live-checked path works; S2 ties do not prove it beats the MLP. Final pre-S3 choice remains gated.
- What prevents leakage? Whole-session assignments, provenance excluded from features, training-only scaler fitting and unchanged thresholds; no final-test retuning.
- Why can a graph be flat or contain gaps? Real values may repeat; unrepresented intervals stay missing. The sample mode is explicitly fabricated.
- Is the server protected right now? Answer from current capture/firewall/policy evidence, not a green model-loaded indicator or old block history. Current default is monitor-only.
- What cannot be reproduced? Lost original raw PCAPs cannot be reconstructed from aggregate exports. Surviving hashes/feature exports and bounded packet samples support narrower checks.
- What is unfinished? #49 source evidence, #50 settings, #51 Linux acceptance, approved S3 release/results, matched four-mode experiments and final report/rehearsal/package acceptance.

## Actual rehearsal and final acceptance

- [ ] All speakers rehearse against the same build and evidence records.
- [ ] Ayden checks technical claims and answers the questions above aloud.
- [ ] Aadi aligns the assembled report/slides with the current measured-results tables and actual course rubric.
- [ ] The team checks demo navigation, keyboard/touch behavior and fallback material.
- [ ] Record the actual rehearsal date, attendees, failures and follow-up actions.
- [ ] Recheck final candidate regression and record platform skips once the final code/evidence exists.
- [ ] Verify report, instructions, citations, package and any required backup demo before December 1's team handoff target; confirm the separate official submission requirements.

This outline does not mark Week 6 Done. Keep the group-sharing Word summary, private data, model files and raw timing samples off GitHub.
