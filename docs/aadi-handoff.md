# Aadi frontend and documentation handoff

Aadi, start the dashboard using the sample data below. You do not need to wait for the live backend or install a VM for this stage.

## Read these first

- [API contract](api-contract.md): proposed field names, types, meanings, and display rules.
- [JSON examples](api-examples.json): made-up sample values for building the page.
- [Dashboard plan](dashboard-plan.md): overall backend and frontend agreement.
- [Trello board](https://trello.com/b/7nOJyLqY/ml-ddos-detector): weekly work and deadlines.

The fields are a version-one draft. Tell Ayden if something needed by the interface is missing; agree changes before building around them. The endpoints are not implemented yet.

## What to build first

Build one simple page with four sections:

| Section | Show |
| --- | --- |
| System status | Capture, model, and firewall status; monitor-only or automatic mitigation mode; last update |
| Traffic chart | Packets per second and bytes per second over time, clearly labeled with their different units |
| Detections | Time, source IP when known, aggregate/source scope, aggregate model score, source-rule evidence, and decision |
| Active blocks | Source IP, reason, confirmed block time, and expiry time |

Keep the first checkpoint small: one readable page showing all four sections from sample data. Styling and live integration can follow. Plain HTML, CSS, and JavaScript are enough; Chart.js is an option for charts. Put frontend source in frontend/ and add simple run instructions when it exists.

## How to use the sample data

The JSON file groups four separate response examples:

- examples.health supplies system status.
- examples.metrics.points supplies chart measurements.
- examples.detections.detections supplies detection rows.
- examples.blocks.blocks supplies active-block rows.

Use these examples as local mock data, with a visible sample-data indication. Keep data loading separate from rendering so we can replace the mock source with API calls later. Do not build the UI around hard-coded example IPs, scores, or timestamps.

## Important display rules

- Show unknown source_ip as Unknown source. An aggregate alert does not identify an attacker.
- Label attack_score as Aggregate model score, not source confidence or accuracy. Source rows reuse the linked aggregate event score; show protocol, rate/share, and qualifying-window evidence separately. Use aggregate_detection_id and attribution from the contract.
- block_requested does not mean a block succeeded. Only confirmed entries from blocks belong in the active-block table.
- Preserve the difference between zero, null/unavailable, and no records.
- Keep timestamps in UTC in data; display Toronto local time with a timezone label.
- Handle loading, empty tables, connection failures, and stale data. A failed request must not look like healthy zero traffic.
- The sample timestamps are fixed examples, not live clock values. Mock mode should not pretend to be a live system.

## What Ayden will provide

Ayden owns the field contract, example responses, and backend endpoints. The planned display endpoints are GET /api/health, GET /api/metrics, GET /api/detections, and GET /api/blocks. Error responses and history limits still need agreement before live integration.

The model predicts aggregate windows; a separate source-rule stage identifies candidates. Keep source_ip nullable for aggregate alerts. Traffic charts show inbound IPv4 TCP/UDP/ICMP to the protected server. Bytes mean IP packet bytes, including IP/transport headers but excluding Ethernet headers. See [design](design.md) for the recorded decisions and pending implementation checks.

Monitor-only is the startup default. The JSON deliberately shows automatic mode and one confirmed 300-second block so you can build the active-block table. This does not authorize automatic enforcement by default. Thresholds and the block cap still need agreement.

Do not implement real block/unblock controls yet. We will specify and test those with the backend later.

## Documentation work

Create the report outline and record how to run the frontend, its libraries, screenshots, and current limitations. Each member writes their own technical contribution; Aadi coordinates and edits the report. The group-sharing Word summary stays off GitHub.

## First checkpoint is done when

- All four sections render from the example data.
- The page handles an unknown source, no detections, and no active blocks.
- Ayden and Aadi review the layout and agree on any field changes.
- Frontend run instructions and the report outline are available.

Work on development. Promote changes to main only after testing and review. Send Ayden the layout and any field questions before spending time polishing the design.

Remaining infrastructure, policy, and dataset work is tracked in [Vince's follow-up issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5).
