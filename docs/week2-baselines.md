# Ali's Week 2 baselines and fixture verification

Task: [W2 | Ali | Record baselines and verify feature fixtures](https://trello.com/c/ZxwJF4Ei).
The work has three parts: normal-service measurements with consistent VM resources,
independent packet-feature fixtures, and generator identity/timestamp review.

## Status and acceptance

| Deliverable | Available evidence | Remaining evidence |
| --- | --- | --- |
| Saved normal-service baseline | Vince reported three trials on November 11 with 180 successful requests. See [the lab report](policy-proposal.md#1-evidence-available-today-and-what-it-cannot-support). | Review the raw exports and capture, and obtain the missing server/client resource and service configuration records. |
| Saved packet fixtures and expected values | Two tiny synthetic Ethernet PCAPs, literal twelve-feature expectations, hand arithmetic, saved-byte hashes, offline and replay tests | Vince's real lab captures still need independent review when shared |
| Generator output/identity/timing review | Current HTTP and SYN/UDP export validation, outcome/slot accounting, UUID and UTC/epoch tests | Matched real scenario exports, server captures, source identities and bounded cross-host clock evidence |

The saved synthetic fixture deliverable is complete. The full Week 2 card remains
In progress until actual VM baseline measurements are retained and reviewed.
A successful software test, local HTTP run, sender log or teammate report does
not fill the remaining lab evidence cells. No service performance target or
improvement claim is introduced here.

## Independent fixture verification

See [week2-feature-fixtures.md](week2-feature-fixtures.md) for the packet ledger,
all twelve calculations, edge cases and exact reproducible commands. Tests use
literal expected values independently of the production feature implementation.

Inbound RST packets remain in version-one packet/byte/TCP/source aggregates and
outside the SYN counts; an ACK flag, if present on a packet, follows the existing
ACK formula. This matches the [PR #18 design decision](https://github.com/aydsman/ML-DDoS-Detector/pull/18)
and does not introduce an RST filter. The fixture explicitly tests an RST without
ACK. Empty gaps do not establish healthy zero-traffic or benign windows.

```sh
./.venv/bin/python -m pytest -q tests/test_week2_feature_fixtures.py tests/test_review_measurements.py tests/test_collect_baseline.py
```

## Collect the actual VM baseline

Use the existing [isolated lab](lab-setup.md). This step runs on `ddos-client`
(`10.10.10.20`), targeting the protected nginx service at `10.10.10.10`. It uses
only Mujtaba's legitimate HTTP client. No simulator traffic or mitigation should
be running during the normal-service baseline. Keep server/client allocations,
service configuration, capture/instrumentation choices and background workload
consistent across repetitions, recording any differences.

1. Use the reviewed Week 2 branch/revision in both VMs and the project Python 3.12
   environment. Record any deliberate component-revision differences. Check the
   route, nginx service and interface using the lab guide. Preserve actual VM
   allocation/snapshot and service evidence, not just the planned setup values.
2. Copy [the resource record template](templates/week2-resource-record.template.json)
   to `results/week2-resources.json` and fill it using the VM host and both guest
   observations. Leave unknown values null and explain them. On Vince's Windows
   host, `VBoxManage showvminfo ddos-server --machinereadable` and the equivalent
   command for `ddos-client` supply allocation/network facts. Save their output
   and the guest/service/clock observations alongside the record. Do not include
   secrets. Merely passing a filled file to the collector does not verify it.
3. From the repository root on the client VM, run:

```sh
./.venv/bin/python -m tools.collect_baseline \
  --target http://10.10.10.10/ --rate 2 --duration 30 \
  --repetitions 3 --timeout 5 --concurrency 1 \
  --resource-record results/week2-resources.json \
  --output results/week2-baseline
```

These predeclared settings produce three separate 30-second request-start windows
at two requested GETs/second. They are an initial collection protocol, not an
agreed performance target. The first trial is retained; no silent warm-up deletion
or best-run selection occurs. Slow responses may finish after a start window and
lower achieved rate. Preserve skipped slots and all failures. HTTPX timeouts are
per operation, not total request deadlines. Stop with Ctrl+C; interrupted/partial
collections retain known exports and do not become completed repetitions.

4. The command prints the absolute `collection.json` path. Inside its UUID folder:

```text
collection.json                 experiment-to-component UUID mapping and provenance
resource-record.json            copied supplied record (extension follows input)
runs/<client-run-uuid>/run.json  unchanged current HTTP export
runs/<client-run-uuid>/requests.csv
```

The manifest records code revision/dirty state, OS/Python/installed dependencies,
settings, per-trial UTC envelopes, CPU/RAM visible to the collector OS, hashes,
and run IDs. It labels the target `lab_baseline_candidate` and leaves acceptance
pending. CPU/RAM observations concern the client OS; they do not prove hypervisor
allocations, target-server resources, stable host load or service configuration.
A dirty checkout must be explained and preserved before accepting measurements.

5. Validate the saved runs and calculate per-run statistics. Set `collection` to
   the UUID directory printed above, then run on Linux/macOS:

```sh
collection=results/week2-baseline/REPLACE_WITH_COLLECTION_UUID
./.venv/bin/python -m tools.review_measurements "$collection"/runs/* \
  --experiment-id REPLACE_WITH_COLLECTION_UUID --output "$collection/review.json"
```

On Windows PowerShell, pass explicit run-directory arguments instead of a shell
glob if the shell does not expand it. The reviewer refuses to overwrite an existing
report; choose a new report filename for subsequent reviews. It never modifies
source files. Preserve the whole collection and referenced resource/service/clock
artifacts for Ali/Vince review, outside Git. Missing external evidence is still a
blocker even when this command returns zero.

## What the review report establishes

`tools.review_measurements` reads **current** `draft-2` HTTP or
`scenario-draft-1` scenario exports. It validates JSON/CSV identities, unique
scheduled indices, finite values, UTC/epoch agreement, counters and state. It
checks the half-open scheduled workload and all accounting equations. Duplicate
JSON keys, duplicate run UUIDs across inputs, missing rows, incompatible schemas,
running/null summaries and contradictory counters fail validation. It hashes
the source bytes it actually read. Older HTTP exports without the additive
scheduled/cancelled counters fail this current-format audit as unavailable;
this does not mean their observed request statistics are false. Do not backfill
missing counters or overwrite those historical artifacts.

For reconciled HTTP attempts it reports:

- Successful attempts / attempted requests under `http_get_status_2xx_v1`
  (complete status 200–299; no payload check or total deadline claim).
- Separate success, invalid-response, timeout, transport-error and unknown counts
  and rates. Interrupted/unexpected client errors are unknown. If unknown outcomes
  exist, the primary success rate is null and bounds are shown. No attempts gives
  null ratios rather than perfect availability.
- Successful-response latency in seconds, sample count, and nearest-rank p50,
  p95 and p99. Failure durations do not enter these quantiles. Nearest-rank p50
  is not the arithmetic median for even sample counts.
- Workload skips/cancellations separately from service failures. Interrupted
  exports can describe completed attempts but are not full-duration trials.

This is descriptive client evidence. `valid: true` means format/accounting checks
passed; it is not a passing lab acceptance test. The report does not automatically
pool repetitions, determine performance targets or mark the card Done.

## Scenario and timestamp/run-label handoff

Validate each preserved SYN/UDP export with the same reviewer:

```sh
./.venv/bin/python -m tools.review_measurements \
  results/scenarios/REPLACE_WITH_SYN_UUID results/scenarios/REPLACE_WITH_UDP_UUID \
  --experiment-id REPLACE_WITH_EXPERIMENT_ID --output results/scenario-review.json
```

The HTTP client, each scenario and the parent experiment have different IDs.
Keep the explicit mapping in the collection/review and the
[experiment record](templates/run-record.template.json). Never copy one
component's UUID over another. `controlled_syn`/`controlled_udp` is generator
intent; it does not label received packets, nearby windows, or detector outputs.
Scenario `sent` is local socket acceptance; `server_received` stays null without
capture evidence. Send errors and interrupted-unknown attempts do not establish
zero delivered packets. Setup-failed runs with no start and all slots cancelled
represent no scenario run, not a zero-load baseline.

ISO/epoch checks compare representations of the same host timestamp to within
one microsecond. Scenario attempt starts must fall between its recorded start
and stop. The stop timestamp follows export finalization, so it is only an upper
observation envelope, not a measured last-packet arrival time. HTTP metadata start
precedes export setup and there is no measured UTC completion/end in the raw
HTTP schema: the reviewer does not manufacture one from monotonic durations.
Collector trial UTC start/end likewise bound the collection call, not wire timing.

Each observed request/send start maps to `[floor(epoch), floor(epoch)+1)` for
inspection. These start counts are not packet counts, capture coverage, or
attack/benign window labels. Cross-host joins require measured offsets and
uncertainty bounds valid for the run; timestamp formatting alone is insufficient.

## Evidence needed to close Week 2

Vince should provide the completed baseline collection plus actual server/client
resource/service records. For the scenario review, retain paired sender UUID
folders and server PCAPs, capture interface/filter and drops, actual source/target
and protocol identity, clock offsets/uncertainty, and exact tested commits. Reuse
existing raw records only if their settings and provenance satisfy the check;
do not redo traffic solely to replace an inconvenient result.

Ali then checks each repetition's denominator and successful latency, resource
consistency, all twelve extracted feature values against an independent reference,
and the run-to-capture mapping. `tools.verify_pcap_features --engine scapy` can
compare eligible real classic PCAPs once supplied; its agreement alone does not
validate source labels or coverage. Vince reviews capture/resource evidence;
Mujtaba reviews generator/run mapping; Ayden can review contract consistency.
Keep the PR targeting `development` for peer review; merge into `main` is later.
