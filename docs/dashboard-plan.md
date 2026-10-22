# Backend and dashboard planning

Status: proposed agreement for Ayden and Aadi to review. These endpoints are not implemented yet. Example values below are mock data.

## Goal

Agree what the dashboard displays and what the backend sends. Aadi can build against saved example responses while Ayden implements the backend. Work on development and promote tested changes to main.

## Responsibilities

- Ayden supplies API definitions, example JSON responses, validation rules, and backend error behavior.
- Aadi builds the browser layout, charts, tables, refresh behavior, and loading/error states.
- Both review one example for each screen before implementation.

## First version

| Display | Proposed endpoint | Required information |
| --- | --- | --- |
| System health | GET /api/health | Capture/model/firewall status, mitigation mode, last update |
| Traffic chart | GET /api/metrics | Timestamped packet and byte rates with explicit scope |
| Detection table | GET /api/detections | Event ID, time, model version, score, decision scope, source if known |
| Active blocks | GET /api/blocks | Source IP, reason, confirmed application time and expiry |

Start with display-only screens. Add controls after the mitigation design is agreed and tested.

## Proposed conventions

- Poll approximately once per second initially; this is a proposal to validate under load.
- Transfer timestamps in UTC ISO 8601 format and display Toronto local time with a visible timezone label.
- Keep packet rates in packets per second and byte rates in bytes per second. Label converted units in charts.
- Include a schema version in responses. Keep feature details within the backend; frontend metrics need clear units and scope.
- Use a stable event ID and deterministic ordering for event lists; agree bounded history and pagination before live integration.
- Distinguish unknown/unavailable values from measured zero.
- Display backend failures and stale data clearly; never imply a failed capture is healthy zero traffic.
- A model score is not verified live accuracy. Record whether a displayed source is identified or unresolved.
- Confirmed firewall actions, not requested actions alone, populate the active-block view.

## Mock health response

```json
{
  "schema_version": "1",
  "updated_at": "2026-10-22T19:00:00Z",
  "capture_status": "running",
  "model_status": "loaded",
  "firewall_status": "available",
  "mitigation_mode": "monitor_only"
}
```

## Mock metrics response

```json
{
  "schema_version": "1",
  "updated_at": "2026-10-22T19:00:00Z",
  "scope": "protected_server_inbound",
  "points": [
    {
      "window_start": "2026-10-22T18:59:59Z",
      "window_seconds": 1,
      "packet_rate_pps": 120,
      "byte_rate_Bps": 24000
    }
  ]
}
```

## Planning session checklist

1. Sketch one page containing health status, traffic chart, detections, and active blocks.
2. Review the table above and agree on displayed fields, units, and scope.
3. Ayden supplies mock examples for health, metrics, detections, blocks, empty data, and errors.
4. Aadi confirms the examples are enough to build the page without guessing backend behavior.
5. Record the agreed contract and unresolved items. Set a short joint integration check before the week ends.

## Done when

Ayden and Aadi have reviewed the layout and example responses, agreed field names and error behavior, and Aadi can build against the examples. This draft alone does not establish agreement.
