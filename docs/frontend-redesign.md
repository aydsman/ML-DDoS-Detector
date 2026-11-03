# City glass frontend redesign

Branch: `feature/frontend-redesign`. Preview: http://127.0.0.1:8002/frontend/ (serve the repository root).

Overview, Traffic, Detections and Blocks share one snapshot, scenario selector, reload control, timestamp and warning. Hash navigation supports Back/Forward without fetching or resetting data. Overview has compact charts; Traffic retains both exact-value disclosures. Existing event/block rendering, ordering, units, data and loader behavior are retained. No API integration or enforcement controls are added.

The selected dusk skyline sits behind smoky glass. Sidebar expands on hover/focus and can be pinned, reserving desktop content space. Page transitions use a 100ms exit and 220ms entrance; initial panels use 350ms with a 50ms stagger. Reduced motion disables animations. Native disclosures, named links, skip navigation and focus outlines support keyboard use. Small/short screens scroll; desktop tables scroll internally.

Browser checks: all six scenarios, stale-data retention and recovery, four-page navigation, unavailable exact measurements, sidebar pin spacing, 1366x768 outer dimensions and 390px width. Full backend regression tests were not rerun for these frontend-only changes.

The original presentation is preserved by tag `frontend-aadi-before-glass-20261102`. Development and main have not been merged. The separate `overview-preview.html` remains an earlier composition reference.
