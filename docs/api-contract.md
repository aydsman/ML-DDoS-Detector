# Dashboard API contract

Version 1 design draft. Owner: Ayden. Frontend: Aadi. These endpoints are proposed and are not implemented yet. Work on development; promote tested changes to main.

This file explains every field in [api-examples.json](api-examples.json). The JSON contains mock data, not measurements or a trained model. JSON cannot contain comments, so explanations belong here.

## How the example file is organized

The example file groups four separate API responses under `health`, `metrics`, `detections`, and `blocks`. These four outer keys organize the example file; the real endpoints return only their corresponding response object.

| Endpoint | Object to read from the example file | Dashboard use |
| --- | --- | --- |
| GET /api/health | health | System status |
| GET /api/metrics | metrics | Traffic chart |
| GET /api/detections | detections | Detection table |
| GET /api/blocks | blocks | Active block table |

For example, Aadi reads `examples.metrics.points` when using the example file, but `response.points` when calling GET /api/metrics.

## Shared response fields

These fields appear at the top of every endpoint response.

| Field | JSON type | Meaning and rules | Example |
| --- | --- | --- | --- |
| schema_version | string | Contract version. Use "1" for this format; incompatible changes require a new version. It is separate from the model version. | "1" |
| updated_at | string | UTC ISO 8601 timestamp when the backend assembled this snapshot. Individual records retain their own measurement/event times. | "2026-10-22T19:00:02Z" |

## System status

| Field | JSON type | Meaning and allowed values | Example |
| --- | --- | --- | --- |
| capture_status | string | Packet-capture state: running, stopped, or error. Running does not prove that no packets were dropped. | "running" |
| model_status | string | Model state: loading, loaded, or error. Loaded means the model is ready for inference. | "loaded" |
| firewall_status | string | Enforcement availability: available, unavailable, or error. Available does not mean any IP is currently blocked. | "available" |
| mitigation_mode | string | monitor_only records detections without automatically blocking. automatic permits the backend policy to request blocks. It does not bypass policy checks. | "automatic" |

## Traffic

The `points` field is an array of measurement objects. An empty array means there are no measurements to display yet. Points are sorted oldest first for charting. Version 1 reports combined incoming IPv4 TCP, UDP, and ICMP traffic to the configured protected server (lab default 10.10.10.10), captured on its lab NIC. It is not a per-source chart. Byte counts use IPv4 Total Length, including IP/transport headers and excluding link-layer headers. Offline/live normalization and capture alignment must be verified before integration; see [design](design.md).

| Field | JSON type | Meaning and rules | Example |
| --- | --- | --- | --- |
| window_start | string | UTC start of the measurement interval. The interval includes its start and excludes its end. | "2026-10-22T19:00:00Z" |
| window_seconds | number | Interval duration in seconds; must be greater than zero. Start with one-second non-overlapping windows aligned to Unix epoch time, using floor(timestamp / window_seconds) * window_seconds. | 1 |
| packets_per_second | number or null | Observed incoming packet count divided by window_seconds. Must be nonnegative. Zero is measured silence; null means unavailable. | 1200 |
| bytes_per_second | number or null | Observed incoming byte count divided by window_seconds. Must be nonnegative. Use the sum of IPv4 Total Length values divided by window_seconds; it must match offline/live extraction. | 240000 |

These are observed capture rates, not guaranteed offered traffic or server throughput. If capture fails, do not fabricate zero-rate points. Report the capture status and leave an unmeasured interval absent, or explicitly use null rates for that interval.

## Detections

The `detections` field is an array of prediction/decision records, sorted newest first by detected_at, then id for ties. An empty array means there are no detection records in the returned history. It does not prove there was no attack.

| Field | JSON type | Meaning and rules | Example |
| --- | --- | --- | --- |
| id | string | Stable unique identifier for this detection record. Refreshing the dashboard must not create a different ID for the same record. | "det-0002" |
| detected_at | string | UTC time inference produced this event, not the start of the attack or measurement interval. | "2026-10-22T19:00:01Z" |
| scope | string | aggregate describes combined traffic; source describes traffic attributed to a particular source. | "source" |
| source_ip | string or null | Source address associated with the event. Required as a valid IPv4 address for source scope; null for aggregate scope. Never invent a source from an aggregate alert. | "192.0.2.10" |
| attack_score | number | Aggregate-window model attack score between 0 and 1 inclusive. For source records this is copied from the referenced aggregate event, not a prediction about that IP. It is not verified accuracy or guaranteed confidence. | 0.94 |
| model_version | string | Identifier of the trained model artifact that produced the score. The example name is a placeholder, not an existing model. | "rf-example-v1" |
| aggregate_detection_id | string or null | null for aggregate records; for source records, ID of the aggregate event supplying the score and attack decision. | "det-0001" |
| attribution | object or null | null for aggregate records; required evidence object for source records, defined below. | See below |
| decision | string | no_action: no alert/block request; alert: record a suspicious event without a block request; block_requested: the policy requested enforcement. | "block_requested" |

A high score alone does not authorize blocking. block_requested is permitted only for source scope with a known source_ip and a satisfied mitigation policy. Monitor-only mode must not create automatic block requests. The model remains aggregate-only. Source rules are documented in [design](design.md); issue #1 tracks their implementation evidence. Default operation is monitor_only. A qualifying source in monitor_only is an alert, never block_requested.

### Source-attribution evidence

These fields are all required inside a source record's `attribution` object. They describe rule evidence, not ML features or a source model score.

| Field | JSON type | Meaning and rules |
| --- | --- | --- |
| protocol | string | tcp, udp, or icmp; grouping is by source IP and protocol |
| packets_per_second | number | Nonnegative source/protocol packet count divided by window duration |
| syn_per_second | number or null | Nonnegative TCP SYN-only count divided by window duration; null for UDP/ICMP |
| packet_share | number | Source/protocol packet share, from 0 to 1 inclusive, using the stated denominator |
| share_basis | string | all_selected_packets only in version one: denominator is all selected inbound packets to the protected host, across supported protocols |
| consecutive_windows | integer | Number of consecutive qualifying windows ending at this event, at least 1 |

For source events, attack_score and model_version must match the referenced aggregate event. The backend must retain or resolve that reference even if it falls outside the current response page. Do not plot source and aggregate records as independent ML predictions.

Approved planning defaults: all_selected_packets as the share basis, three qualifying windows, 300-second blocks, and a configurable provisional cap of 20 active blocks. Use 0.5 as an experimental aggregate model-score threshold, then tune using validation data. Per-protocol rate thresholds, minimum traffic share, final model threshold, NIC, and management/gateway allowlist values still require evidence before automatic enforcement.

The mock responses deliberately show automatic mode and one confirmed block to demonstrate the UI. Normal startup must default to monitor_only. The source example assumes three preceding qualifying windows, configured thresholds satisfied, an allowlist check passed, and available block capacity; the small metrics snapshot is not the entire evidence history.

## Active blocks

The `blocks` field is an array of blocks confirmed active by the firewall, sorted newest first by blocked_at, then id for ties. An empty array means no active blocks are reported. Pending or failed requests do not belong here. Remove entries after confirmed removal/expiry; reconcile with the firewall so the list does not silently retain stale rules.

| Field | JSON type | Meaning and rules | Example |
| --- | --- | --- | --- |
| id | string | Stable unique identifier for a block action. This is separate from a detection ID; multiple detections may contribute to one block. | "block-0001" |
| source_ip | string | Valid IPv4 address confirmed blocked. Cannot be null. | "192.0.2.10" |
| reason | string | Short readable explanation of why the policy requested the block. Include a detection reference when useful. It is display text, not a firewall command. | "Source policy satisfied for 3 windows; attribution event det-0002" |
| blocked_at | string | UTC time the backend confirmed enforcement. Sending a request alone does not set this timestamp. | "2026-10-22T19:00:01.200Z" |
| expires_at | string | Planned UTC expiration; must be later than blocked_at. Version 1 supports temporary blocks only. Reaching the time alone is not proof the firewall removed a rule. | "2026-10-22T19:05:01.200Z" |

## Rules shared by backend and frontend

- Field names are case-sensitive. Use packets_per_second and bytes_per_second consistently; older draft names packet_rate_pps and byte_rate_Bps are replaced.
- All listed fields are required in their corresponding object. Only fields explicitly marked nullable may contain null. Missing fields are contract errors.
- Use JSON numbers for rates, duration, and scores, not strings containing units.
- Use UTC timestamps ending in Z; fractional seconds are allowed. The frontend displays local time with its timezone label.
- The frontend shows loading, empty-data, unavailable-data, connection-error, and stale-data states clearly. A failed request must not erase an alert or imply the system is healthy.
- Frontend polling starts at approximately one-second intervals. Avoid overlapping requests. Evaluate the overhead before finalizing the refresh rate.
- Keep the first version display-only. Mitigation controls and their request/error schemas will be specified separately before implementation.
- Agree history limits and pagination before live integration. These examples are small snapshots and do not define unlimited retention.
- This is an API design draft, not an executable JSON Schema or backend implementation. Backend validation models can be added after review.

## Decisions still requiring review

- Ayden and Vince: validate rate/minimum-share settings, implement agreed epoch alignment and normalization, verify allowlist addresses, and provide offline/live parity evidence. The aggregate model, separate source rules, and IP-byte definition are now recorded in design.md.
- Vince and Ali: verify dataset files, ground truth, exclusions, sensitivity to the provisional 80% label threshold, and independent splits before training; see issue #3.
- IPv4-only scope is confirmed. IPv6 remains deferred until capture, API, and firewall contracts are updated together.
- Ayden and Aadi: confirm the display fields, history limits, error responses, and stale-data behavior before treating version 1 as finalized.

Remaining infrastructure, policy, and dataset work is tracked in [Vince's follow-up issue #5](https://github.com/aydsman/ML-DDoS-Detector/issues/5).
