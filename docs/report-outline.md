# Final report outline — ML-DDoS-Detector

Coordinator/editor: Aadi. Week 1 draft, October 26, 2026. Confirm the instructor's rubric, length, format, and citation requirements before final assembly. Each member writes their own component; Aadi consolidates and edits.

| Section | Content and evidence expected | Contributor |
| --- | --- | --- |
| Title page and abstract | Course, team, objectives and evidence-supported findings; write abstract last | Aadi; all verify |
| 1. Introduction | Problem, objectives, isolated-lab scope, SYN/UDP focus, success criteria | Aadi, Ayden |
| 2. Background | DDoS detection approaches, model rationale, dataset and library citations | Ayden; all supply references |
| 3. Architecture | Capture â†’ aggregate features â†’ inference â†’ source attribution â†’ mitigation; API/dashboard boundaries and diagram | Ayden, Vince; Aadi assembles |
| 4. Lab and reproducibility | VM topology, versions, interfaces, setup commands, verified captures | Vince |
| 5. Dataset and features | Verified files, labels, provenance, window definitions, exclusions, independent splits, leakage prevention | Vince, Ayden; Ali checks ground truth |
| 6. Model | Random Forest training, preprocessing, settings/seeds, validation threshold, saved artifacts; MLP only if implemented | Ayden |
| 7. Traffic and mitigation | Legitimate workload, controlled scenarios, logs, firewall application/expiry/cleanup; attribution and allowlist policy | Mujtaba; Ayden supplies policy |
| 8. Dashboard and API | Four sections, aggregate/source distinction, units, error/stale/empty behavior, mock/live boundary, screenshots | Aadi; Ayden reviews API |
| 9. Experimental method | No defense, monitor-only, simple rules, ML mitigation; run IDs, independent ground truth, metric collection, acceptance checks | Ali; all supply component evidence |
| 10. Results | Precision, recall, F1, false positives, latency, availability, resource/capture health, legitimate-client recovery; figures tied to runs | Ali; Ayden and Mujtaba supply outputs |
| 11. Discussion | Interpretation, generalization, spoofed sources, capture loss, data limitations, fairness of comparisons | All; Aadi edits |
| 12. Conclusion | Verified achievements, limitations, future work | Aadi; all review |
| References and appendices | Citations, run instructions, configuration, feature/API definitions, test evidence, contribution table | Everyone; Aadi consolidates |

## Contribution handoff

Each owner supplies prose, source paths/commit, exact commands and versions, evidence, citations, and known limitations. Leave results as placeholders until experiments exist. Do not present mock dashboard values as measured results. Keep large captures and credentials outside Git; the group-sharing Word summary stays off GitHub as required by the handoff.

## Week 1 deliverables and review

- Dashboard: `frontend/`; startup and manual acceptance checks: `frontend/README.md`.
- Examples: `docs/api-examples.json`, clearly labelled as invented data in the dashboard.
- The outline and contribution assignments were shared in a comment on [Aadi's Week 1 Trello card](https://trello.com/c/ZRF6obnC). Source is published in PR #10; Ayden approved the outline and responsibilities. Other team acknowledgements remain to be collected.
- Ayden approved the week-one mock layout/API review in PR #10. The proposed history limits/freshness defaults are provisional; finalize pagination, error responses, per-endpoint freshness, and partial-failure behavior before live integration.

## Final assembly checklist

- [ ] Confirm instructor rubric and submission format.
- [ ] Collect each member's section, evidence, citations, and limitations.
- [ ] Check descriptions against implemented code.
- [ ] Label figures with units, scenario and run ID; mark mock screenshots explicitly.
- [ ] Verify references and contribution attribution.
- [ ] Complete team review and export final submission.
