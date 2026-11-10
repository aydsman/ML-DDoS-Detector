# Mock dashboard — Weeks 1 and 2

## Week 2 verification (November 10)

The current redesigned Overview, Traffic, Detections and Blocks views use the shared API fixture. Added display-contract validation in `validation.js` rejects missing arrays/rates, invalid timestamps, negative rates, invalid scores, missing source evidence and invalid block expiry before a snapshot is displayed. Invalid responses use the existing error path and retain the previous successful snapshot as stale.

Use **Slow sample load** to observe the loading message and disabled controls for 1.5 seconds, and **Malformed response** to demonstrate rejected data and stale retention. Existing zero, empty, capture-unavailable, stale and connection-failure demos remain available. These are mock scenarios; live requests/refresh remain Week 3 work.

Checks: `node --test tests/frontend-validation.mjs tests/frontend-status.mjs tests/frontend-graphs.mjs` (23 passed); Python suite (492 passed, 4 skipped). Browser verified all eight scenarios, recovery, detection evidence and the confirmed-block table. [Week 2 block screenshot](../docs/screenshots/week2-blocks.png). Review is pending; no live-backend readiness is claimed.

Aadi's display-only dashboard reads the shared `docs/api-examples.json`. Plain HTML/CSS/JavaScript and native SVG; no external libraries, fonts, npm install, or build step.

## Start from the repository root

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1
```

Linux:

```sh
./.venv/bin/python -m http.server 8000 --bind 127.0.0.1
```

Open http://127.0.0.1:8000/frontend/. Stop with Ctrl+C. Serve the repository root so the JSON path resolves; do not open HTML directly as a file. This is a local development server.

## Structure

- `index.html`: sections and demo controls.
- `styles.css`: responsive layout.
- `data.js`: data loading and isolated mock scenario transformations; never modifies the source JSON.
- `app.js`: rendering, Toronto times, exact measurement tables, source evidence, and error handling.

Future API loading belongs in `data.js`. Agree polling, partial failures, history limits/pagination, and freshness thresholds with Ayden first. No live API calls or block/unblock controls exist in this prototype.

## Acceptance checks

1. Representative activity: four health cards, two charts, two detections, one confirmed block. Compare to the JSON. Aggregate source is Unknown source; the source score is explicitly copied from its aggregate event.
2. Expand exact-value tables. Check separate packets/s and bytes/s units, and Toronto timestamps.
3. No traffic or events: explicit empty states, no fabricated zero rates.
4. Capture unavailable: error status and unavailable rates; previous example events remain visible.
5. Stale snapshot: prominent stale banner. Fixed timestamps never pretend to be live.
6. Connection failure after loading: error banner retains prior data as stale. Representative activity recovers.
7. Actual initial-load failure: block `api-examples.json` in browser developer tools and reload; no healthy measurements should appear.
8. Phone width and keyboard: controls/disclosures remain usable; wide tables scroll within their containers.
9. Measured zero traffic: both rates display 0, with no detections or blocks. This is distinct from no measurements and null/Unavailable.

## Limitations and review

Only the two supplied chart points are shown. Mock staleness is selected explicitly, not inferred from historical timestamps. Schema versions are checked; full backend payload validation remains integration work. Historical blocks describe the saved snapshot, not current firewall state. Ayden approved the week-one mock/layout review on PR #10; live integration remains separate.

Report outline: `docs/report-outline.md`. Each teammate supplies their own section and evidence.

## Verification evidence

Browser verification covered representative values, all four alternate scenarios, error recovery, and a 390px viewport without document overflow. Both JavaScript files passed module syntax checks; the existing Python suite passed (4 tests). These checks validate the prototype, not model quality or live backend behavior.

Saved mock screenshots: [desktop](../docs/screenshots/dashboard-desktop.png) and [mobile](../docs/screenshots/dashboard-mobile.png). Label them as mock data in the report. The outline and contribution assignments were shared on Aadi's Week 1 Trello card; source is published in PR #10 and Ayden's week-one review is approved.

October 28 recheck: representative, measured-zero, empty, unavailable, stale, connection failure, and recovery scenarios passed in the browser, with no captured console errors. The local preview requires the server command above to remain running. See the [Week 1 readiness record](../docs/week1-readiness.md) for remaining handoff items.
