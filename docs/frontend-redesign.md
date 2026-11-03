# Frontend glass redesign

Branch: `feature/frontend-redesign`. The implementation changes presentation in `frontend/styles.css` only. Aadi's `index.html`, `app.js`, `data.js` and shared API sample JSON remain byte-for-byte unchanged from the starting version.

## Preview

Serve the repository root with Python's local HTTP server and open `/frontend/`. The review preview uses `http://127.0.0.1:8001/frontend/` to avoid the old stylesheet cached on port 8000. It remains a mock dashboard, not live inference/firewall integration.

## Verified behavior

Browser checks covered representative data; no measurements/events; measured zero; capture unavailable (unavailable rather than zero); stale snapshot; simulated connection failure retaining the last snapshot; recovery; reload; and exact-value disclosures. All health indicators, chart data/units, detection/block fields and Toronto timestamps are retained.

At a 390px viewport, health cards use two columns, charts stack, and wide detection/block tables scroll within their containers without document-level horizontal overflow. The viewport was reset afterward. Keyboard focus and reduced-motion styles are retained. No new navigation, metrics, controls, sample history, dependencies or backend calls were added.

## Restore the original presentation

A named annotated tag preserves the exact starting checkout: `frontend-aadi-before-glass-20261102`.

Before merge, commit any work on the redesign branch, then `git switch development` to view the shared version. For a new comparison branch at the exact original snapshot, use:

```sh
git switch -c compare/aadi-original frontend-aadi-before-glass-20261102
```

Do not reset or force-push shared history. If the redesign is merged later and needs undoing, revert its merge/change through the normal reviewed workflow. This preview does not merge the redesign into development or main.
