# City glass frontend redesign

Branch: `feature/frontend-redesign`. Local review: serve the repository root and open /frontend/. Temporary preview addresses change with the host network; the old 192.168.68.69 address is no longer valid.

## Presentation

Locally bundled Manrope (license in frontend/assets/fonts/OFL.txt), four inline vector icons in a dark centered capsule, hover/keyboard labels with Escape dismissal, and a frosted selected circle. Touch links navigate directly. A white circular arrow expands the sidebar, reveals labels and reserves layout space. Narrow windows move navigation above the content. No pin state remains.

The supplied 3840x2160 sunset photo replaces the earlier low-resolution skyline. A fixed overlay darkens it; blur is limited to panel backdrops. Content is bounded to 1560px with compact Overview height and larger Traffic plots. Small screens scroll normally; tables retain internal scrolling. Project attribution and API-schema information are restored.

Charts reflow their SVG coordinates on container resize while retaining text size, data, null gaps, scales and units. All views share the snapshot, demo selector, reload, timestamp and warnings. Exact measurements remain on Traffic. No new backend calls or project controls are introduced.

## Validation

Browser checks covered 1366x768, 2560x1440, 3440x1440 and 390x844. Overview fit the laptop without outer scrolling; wide layouts capped at 1560px and mobile had no horizontal document overflow. Checked all six scenarios, stale-data retention/recovery, four views, Back navigation, exact packet measurements, keyboard labels and Escape dismissal. Reduced-motion and forced-color fallbacks remain in CSS. Physical touch input, actual browser zoom and real PC display quality still need user visual review.

## Recovery

Original snapshot: tag `frontend-aadi-before-glass-20261102`. Development and main remain unchanged. Review PR #21 before merging. Revert through normal Git workflow rather than resetting shared history.

## Warm charcoal refinement

General toolbar/health glass opacity reduced by eight percentage points (approximately 75/79% to 67/71%); general chart panels similarly reduced from 82/85% to 74/77%. Tint is warm charcoal. Warnings and event/block table surfaces retain darker backgrounds. Desktop widths of 1800px and above use approximately 125% interface sizing and a 1950px content cap; laptop sizing is retained.

Verified Overview dimensions at 2560x1440, 1920x1080 and 1366x768 without outer scrolling. Checked mobile width, detection records and failure/recovery display. No application logic or data changes in this refinement.


## Sidebar, glass and motion update (November 3)

All general surfaces, including the sidebar, now use shared warm-charcoal glass at 48–52% opacity with 18px backdrop blur. Warning backgrounds and sticky table headers retain stronger contrast. The photo stays sharp outside glass. The expanding sidebar reserves space and resizes chart geometry; at widths <=850px navigation moves above the content; short desktop windows retain the left rail. Four existing destinations remain.

Two focusable, display-only sidebar summaries describe the **fixed demo snapshot**, never live safety. Empty detection history reads “No detection records,” not “No attack.” Mitigation describes both configured mode and confirmed blocks in the snapshot because monitor-only mode may coexist with blocks. Stale/request-failure states override both summaries; missing initial data is unavailable. Capture/model failures make detection unavailable; firewall failure makes mitigation unavailable. A live current-attack indicator still needs backend observation coverage and freshness semantics. No contract fields or enforcement controls were added.

Page content fades/rises 6px with 40ms staggering; glass surfaces avoid opacity animation to keep backdrop rendering stable. Health cards lift 2px on hover. Large panels highlight without moving. Only visible headline rates tween between finite measurements over 400ms; exact tables and screen-reader values update immediately. Navigation alone does not restart counters; missing values never tween from zero. Reduced motion disables movement and counting. Scrollbar tracks are transparent, with rounded translucent thumbs where the browser supports styling.

Connection investigation: the old preview address no longer belonged to the laptop and its server was absent. Restarted a limited preview serving frontend assets plus docs/api-examples.json. Data loading succeeds on the new local preview; the old screenshot's precise historical failure cannot be reconstructed. Failed requests continue retaining stale snapshots and now give a clearer reachability message.

Validation for this update: eight status-logic tests (`node --test tests/frontend-status.mjs`), 14 existing contract tests, JavaScript syntax and diff checks. Browser exercised all six scenarios, exact Traffic measurements, detection attribution/block fields, keyboard sidebar toggle, and responsive expanded layouts. Browser zoom, physical touch, OS reduced-motion preference and cross-device LAN reachability require Aadi's final review. Earlier viewport evidence above describes the previous revision.


Follow-up: reduced general glass opacity another 14 percentage points (62–66% to 48–52%), applied the shared glass to the sample badge/standard notice and softened warning/table-header fills. Removed the height-only top-navigation breakpoint that incorrectly moved the rail above content in short desktop browser panes.


Demo history refinement: docs/api-examples.json now includes 30 contiguous one-second measurements with low-volume variation, a short burst and a sustained rise. Original final readings, event/block records and snapshot timestamps are preserved. The extra history is explicitly fabricated; it is not a measured attack or evidence of successful blocking. The existing zero/empty/unavailable/stale/failure scenarios still apply to the shared snapshot.


### Graph inspection and sidebar motion (November 3)

Graph entrances animate only recorded plot coordinates and the last valid marker from the fixed zero baseline for 500ms with cubic ease-out. This is presentation, not recorded traffic rising from zero. Axes, scale, values and exact tables stay fixed. Entrances replay on Overview/Traffic entry, never on reload or rail resize. Leaving, resizing, reduced motion or hiding the document finishes/cancels the animation. Refresh replaces measurements immediately; future live integration must interpolate from prior data, not invoke the entrance.

Each graph has one latest-valid marker. Null and absent windows break lines; isolated readings use short ticks. Trailing unavailable windows keep an unavailable headline and identify the older marker as last available. Pointer inspection snaps to recorded windows and does not cross missing intervals. Keyboard: Tab to the graph, Left/Right, Home/End, Escape. Touch: tap a reading; tap outside or scroll to dismiss. Exact tooltips are viewport-clamped, and inspection starts after the entrance. Refresh retains chart focus and open exact tables.

The rail expands/reflows over 300ms; labels fade without stretching; a separate hover/focus highlight moves between links while selected-page styling persists. Flyouts render outside the scrollable inner rail to avoid clipping in short desktop windows. Narrow screens retain top navigation and readable status descriptions. No data contract, backend, scenario, detection/block detail or status semantics change.

Verification: `node --test tests/frontend-graphs.mjs tests/frontend-status.mjs`; contract pytest checks; browser keyboard inspection/dismissal, sidebar expansion/reflow, unavailable and zero scenarios, and 390px, 1366px, 1920px short-height and 3440px layouts. Physical touch and a screen reader still merit human review.


Sidebar follow-up: the desktop capsule stays vertically centred at every window height, including while expanded. The inner rail permits vertical scrolling only when needed and never shows a horizontal scrollbar. Fixed status-row heights keep icons stable as descriptions appear. A separate frosted selection surface now glides between destinations over 300ms, alongside the hover highlight and label reveal.
