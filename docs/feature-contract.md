# ML feature contract, version 1

Status: version-one baseline specification approved for week-one planning. This is not evidence of a trained model or complete live capture/API integration. This feature schema version is separate from API schema_version and model_version. [feature-contract.json](feature-contract.json) records the ordered names, units, and logical types. `ddos_detector/config.py::FEATURE_NAMES` currently matches this order. Unknown flags use None as approved in PR #8. Retain the documented inbound SYN/ACK formulas for baseline validation, without claiming they measure server handshake completion; review usefulness on validation data before choosing the final model.

## Component inputs and outputs

| Producer -> consumer | Input/output agreement |
| --- | --- |
| Vince's capture adapter -> shared extractor | Time-sorted normalized Packet records: ts (finite epoch seconds), src (IPv4 source string), proto (tcp/udp/icmp), size (integer IPv4 Total Length bytes), flags (observed TCP flags when available). Adapter filters inbound-to-victim packets; Packet has no destination field, so the helper cannot enforce that filter itself. |
| Windowing -> feature extractor | Positive finite window_seconds, epoch-aligned start-inclusive/end-exclusive boundaries, selected packet records, and separate capture-coverage/skip diagnostics. Do not imply coverage from merely seeing a packet. |
| Feature extractor -> Ayden's model | Twelve numeric features in the exact order below. Keep window times, victim, labels, source addresses, and provenance outside the model vector. |
| Model -> attribution policy | Aggregate model score in [0,1], artifact version, referenced window, and decision using the configured threshold. Experimental score threshold starts at 0.5. |
| Attribution policy -> Mujtaba's firewall adapter | Proposed interface requirements: source IP, reason/event reference, unique request identifier, and 300-second TTL. Validate allowlist and capacity before a request. Exact request/result schema and failure handling still need joint agreement before implementation. |
| Firewall adapter -> backend | Confirmed apply/remove status and timestamps, expiry target, and structured failure information. Only confirmed active blocks enter GET /api/blocks; retries must not create duplicate rules. |
| Backend -> Aadi's dashboard | Four separate JSON responses defined in api-contract.md and mocked in api-examples.json. Source records link to aggregate predictions rather than asserting a source-level ML score. |

## Ordered features

| Position (1-based) | Name | Logical type | Unit |
| --- | --- | --- | --- |
| 1 | packet_rate | number | packets/s |
| 2 | byte_rate | number | bytes/s |
| 3 | syn_count | integer | packets |
| 4 | syn_ack_ratio | number | ratio |
| 5 | syn_no_ack_share | number | fraction |
| 6 | pkt_size_mean | number | bytes |
| 7 | pkt_size_std | number | bytes |
| 8 | unique_src_ips | integer | addresses |
| 9 | src_ip_entropy | number | bits |
| 10 | tcp_share | number | fraction |
| 11 | udp_share | number | fraction |
| 12 | icmp_share | number | fraction |

Definitions and range constraints are in the JSON and [design](design.md). Logical integer counts can be emitted as JSON integers or integral numeric values (the existing empty helper returns 0.0); the model vector converts all twelve inputs to finite float64 values in feature_names order. Never rely on arbitrary dictionary or CSV column order. Fraction features are in [0,1]; syn_ack_ratio is nonnegative and can exceed 1. Packet size standard deviation is population, not sample.

## Missing, empty, invalid, and fragmented data

The numeric/name/version guard is now implemented as ddos_detector.contracts.feature_vector. It rejects invalid records and emits ordered Python floats for a float64 model conversion. Coverage, labeling, fragment normalization, and model execution are still separate pipeline responsibilities; the extractor helper itself does not enforce them.

- Require all twelve feature names exactly once with no extras. Reject missing fields, null, NaN/infinity, negative numbers, fractions outside [0,1], and nonintegral count values. Do not silently impute them.
- A successfully monitored empty window has zero-valued features; its chart rates can be zero. Exclude it from training and inference, emit no attack prediction, and break the source streak. This is distinct from how the low-level helper currently returns zeros when called with an empty list.
- Capture failure or incomplete/unknown interval coverage means unavailable measurements. Do not call the model with a fabricated all-zero vector; do not extend source streaks. Surface capture status and use null rates or absent intervals in the dashboard.
- Non-IP, IPv6, unsupported protocols, invalid IP lengths, and incomplete IP headers are skipped with diagnostic reasons. Usable truncated IPv4 packets use declared IP length, not captured byte count; Vince's fixtures must prove the rules.
- Non-first fragments may contribute packet/byte/protocol/source counts but have no readable transport flags. Do not infer observed flags from missing headers. The implemented Packet.flags supports None for unavailable flags and preserves observed zero. SYN/ACK counts and denominators use known flags only; unknown-flag packets still contribute to source/protocol/size aggregates.
- Inputs must be sorted by timestamp. Live late/out-of-order packet handling and coverage detection need Vince's adapter policy and tests; do not silently reassign finalized windows.

## Memory bound

The streaming aggregator tracks at most `max_sources_per_window` (default 10,000) distinct source IPs per window. Packets from further sources still count in every other feature, but `unique_src_ips` and `src_ip_entropy` are then computed over tracked sources only. The window record sets `capped` and `untracked_source_packets` outside the model vector. Feature definitions and the schema version are unchanged.

Finalizing a window does not depend on the number of packets: size statistics are computed from the per-size histogram. A window with `capped` set has incomplete source-diversity features, so it is excluded from version-one training and inference and must not be scored by an exact-contract model. Only uncapped windows are valid model input.

## Model compatibility and completion gates

Each future saved model must record feature_schema_version, exact feature_names/order, dtype, window_seconds, capture scope, packet-size definition, preprocessing, model version, score interpretation, and selected decision threshold. The loader must reject an incompatible schema/order instead of guessing. The version/name/numeric input guard is implemented, but model artifact loading and metadata compatibility checks remain future work.

Any feature addition/removal/reordering or meaning change requires a new feature schema version and corresponding model retraining/validation; do not load an older model against changed definitions. Version one is the explicit baseline interface. A trained artifact must not be certified until the actual dataset/labels and capture parity are verified. Validation may show that an inbound SYN-related feature is redundant; changes must create a new feature version rather than silently changing version one.

## Week-one status

- Completed planning: component boundaries, versioned ordered feature specification, API examples, approved baseline decisions, and the reviewed Aadi handoff.
- Implemented support: ordered input guard, shared IP normalization, explicit unknown flags, and epoch-aligned windowing, with 46 tests passing on the integrated Python suite.
- Next-stage prerequisites: verify the real dataset manifest/ground truth/splits and label sample, actual offline/live adapters and coverage, runtime allowlist, policy tuning, and model artifacts under issue #5. Week-one planning completion does not certify these.

Aadi's frontend/report source is merged from PR #10 and Ayden independently reviewed the mock layout and scenarios. History/error/staleness defaults remain provisional for live API integration.

Dataset selection and expected label cases: [dataset-plan.md](dataset-plan.md). Acceptance evidence and remaining implementation prerequisites: [week1-status.md](week1-status.md).
