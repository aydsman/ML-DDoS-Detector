# City glass frontend redesign

Branch: `feature/frontend-redesign`. Shared preview: http://192.168.68.69:8005/frontend/ (laptop awake, same LAN). Local preview: http://127.0.0.1:8002/frontend/.

## Presentation

Locally bundled Manrope (license in frontend/assets/fonts/OFL.txt), four inline vector icons in a dark centered capsule, hover/keyboard labels with Escape dismissal, and a frosted selected circle. Touch links navigate directly. No sidebar expansion or pin state remains.

The supplied 3840x2160 sunset photo replaces the earlier low-resolution skyline. A fixed overlay darkens it; blur is limited to panel backdrops. Content is bounded to 1560px with compact Overview height and larger Traffic plots. Small screens scroll normally; tables retain internal scrolling. Project attribution and API-schema information are restored.

Charts reflow their SVG coordinates on container resize while retaining text size, data, null gaps, scales and units. All views share the snapshot, demo selector, reload, timestamp and warnings. Exact measurements remain on Traffic. No new backend calls or project controls are introduced.

## Validation

Browser checks covered 1366x768, 2560x1440, 3440x1440 and 390x844. Overview fit the laptop without outer scrolling; wide layouts capped at 1560px and mobile had no horizontal document overflow. Checked all six scenarios, stale-data retention/recovery, four views, Back navigation, exact packet measurements, keyboard labels and Escape dismissal. Reduced-motion and forced-color fallbacks remain in CSS. Physical touch input, actual browser zoom and real PC display quality still need user visual review.

## Recovery

Original snapshot: tag `frontend-aadi-before-glass-20261102`. Development and main remain unchanged. Review draft PR #21 before merging. Revert through normal Git workflow rather than resetting shared history.

## Warm charcoal refinement

General toolbar/health glass opacity reduced by eight percentage points (approximately 75/79% to 67/71%); general chart panels similarly reduced from 82/85% to 74/77%. Tint is warm charcoal. Warnings and event/block table surfaces retain darker backgrounds. Desktop widths of 1800px and above use approximately 125% interface sizing and a 1950px content cap; laptop sizing is retained.

Verified Overview dimensions at 2560x1440, 1920x1080 and 1366x768 without outer scrolling. Checked mobile width, detection records and failure/recovery display. No application logic or data changes in this refinement.
