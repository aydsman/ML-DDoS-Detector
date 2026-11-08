# Controlled SYN and UDP scenarios

Owner: Mujtaba. W2 task: [bounded lab scenarios](https://trello.com/c/0zxzMJOm).
This module implements the sending component, not detection or a benchmark.
Vince reported repeatable live VM runs at `f5c75a5`; see the evidence below.
The setup-failure fix still needs his recheck, and experiment-format review
remains pending. No additional live scenario was executed for this fix.

## Offline preview

From the repository root, after installing `requirements.txt`:

```powershell
.\.venv\Scripts\python.exe -m ddos_detector.scenarios --protocol syn --rate 10 --duration 5
.\.venv\Scripts\python.exe -m ddos_detector.scenarios --protocol udp --port 9999 --rate 10 --duration 5
```

Without `--execute` these commands print a plan, open no sending socket, perform
no ARP, and create no results. Preview works on Windows. Scapy is already a
project dependency; no new packages are required.

## Execute in Vince's isolated lab

Use only `ddos-attacker` (10.10.10.30), with its isolated `ddoslab` NIC connected
to the protected server (10.10.10.10). Follow [lab setup](lab-setup.md), including
disconnecting the attacker's NAT adapter for experiments. Confirm the selected
interface/address and direct server route with Vince before sending. The program
validates the direct route and interface address; it does not inspect the VM
hypervisor's isolation settings.

From the repository root on the attacker VM:

```bash
# Preview first, without root privileges.
./.venv/bin/python -m ddos_detector.scenarios --protocol syn --rate 10 --duration 5

# Separate finite runs. Raw Ethernet sending requires root on Linux.
sudo ./.venv/bin/python -m ddos_detector.scenarios --protocol syn --target 10.10.10.10 --interface enp0s8 --port 80 --rate 10 --duration 5 --output results/scenarios --execute
sudo ./.venv/bin/python -m ddos_detector.scenarios --protocol udp --target 10.10.10.10 --interface enp0s8 --port 9999 --rate 10 --duration 5 --output results/scenarios --execute
```

Only the fixed project server address is accepted. Ports are configurable;
coordinate UDP port 9999 with Vince/Ali. An open UDP service is not required to
send a UDP packet, but closed ports may produce ICMP responses. TCP SYNs do not
complete a TCP handshake, and the attacker's kernel may send resets in reply to
SYN-ACKs. Capture on the server to distinguish these effects from the offered
inbound scenario. Do not disable kernel protections to suppress responses.

Limits: 1-1000 packets/second, positive duration up to 60 seconds, and at most
10,000 scheduled packets per run. Defaults are 10 packets/second for 5 seconds.
There are no spoofed sources, amplification requests, flood mode, or background
workers. These are initial bounded component settings; they are not tuned to
trigger the model or prove mitigation performance. A change to limits or lab
addresses requires review.

The sender uses a monotonic fixed grid. It skips elapsed slots instead of
replaying a backlog. Actual sending may be slower than requested, especially
with VM timer stalls. Packet construction and socket operations add jitter.
The duration is a request-start window; an already executing socket send may
finish afterward. The program waits through the requested window on ordinary
completion. It reports measured duration and achieved local send rate.

Press **Ctrl+C** to stop. No process or worker remains sending after exit.
The program finalizes collected records and closes its socket. A send exception
stops the scenario rather than repeatedly retrying. Ctrl+C during a socket send
records an uncertain attempt, because it cannot establish whether the kernel
accepted that packet. SIGKILL, power loss, or an interruption during finalization
can leave an incomplete export; never treat one as a complete run.

Exit codes: 0 complete, 1 send failure, 2 invalid settings/setup/export failure,
130 interrupted. Complete means the scheduling window finished; inspect skips
and errors before judging whether the intended load was achieved.

## Records and evaluation handoff

Each execution creates a new UUID directory under `--output`, containing:

- `run.json`: `scenario-draft-1`, run ID, controlled protocol, target/port,
  interface, real source IP, rate/duration settings, UTC start/stop, state and
  summary. State begins as `running` with a null summary. Terminal states are
  `complete`, `interrupted` or `failed`. The additive `error` field is normally
  null; a setup failure records its `phase`, exception `type` and `message`.
- `activity.csv`: run ID, 1-based scheduled packet index, UTC `started_at`,
  matching Unix `epoch_seconds`, send duration in `elapsed_ms`, IPv4 byte length,
  outcome and exception class. Slot gaps are skipped/cancelled work. Rows are
  flushed after each completed attempt.

`sent` means the local socket accepted a whole frame; it does not prove server
receipt. `send_error` means sending raised an exception; even a failed send is
not proof that no packet arrived. `interrupted_unknown`/`unknown` mean transmission
could not be confirmed. IPv4 byte length includes IP and transport headers,
excluding Ethernet; CSV send duration is not HTTP latency or detection latency.

The summary reconciles:

```text
scheduled_slots = attempted + skipped_due_to_lag + cancelled_slots
attempted = sent + send_errors + unknown
```

Normal completion assigns remaining missed slots to lag. A stopped or failed
run assigns remaining unsent work to cancellation. Finalization rebuilds CSV
from collected records before atomically publishing the JSON summary, recovering
rows interrupted before or during their incremental write. A write/reconciliation
failure leaves the export incomplete. Run directories are never reused.

Startup route/ARP/socket or platform failure now finalizes as `failed`, with a
UTC `stopped_at`, an `error` with `phase: setup`, and a zero-attempt summary.
`started_at` remains null because the scenario never began. Every scheduled slot
is cancelled; send-error and lag counters remain zero. CSV contains its header
and no attempt rows. The zero elapsed time/rate describe a scenario that did not
start, not measured traffic over the requested duration. Setup ARP probes are
not scenario packet attempts. Ctrl+C during setup records `interrupted`, the same
zero-attempt/cancellation accounting and a KeyboardInterrupt error, with exit 130.
The CLI prints the export path and returns 2 for other setup failures.

This terminal record is written only when export initialization succeeded and
pre-send setup failed. Invalid command settings are rejected before creating a
directory. Export initialization, finalization or metadata I/O failure, a process
crash, or forced termination can still leave an incomplete export. Such files
must not be presented as a verified zero-attempt run. Existing unfinished exports
are never rewritten by this fix. The `results/` directory is gitignored.

This is a separate **draft** scenario schema, not a silent revision of the HTTP
client's `draft-2` format or Ali's proposed experiment schema. Ali should map each
scenario `run_id` into the experiment's traffic-run references and preserve both
files. Record the code commit, experiment ID, clock synchronization and capture
times in the experiment manifest. A detector prediction must not supply the
scenario's ground-truth label. Timing an intended scenario alone does not prove
which packets arrived, nor does it label all packets in an overlapping window.

## Reported lab evidence and remaining checks

Vince's [PR #16 review](https://github.com/aydsman/ML-DDoS-Detector/pull/16#pullrequestreview-5718448394)
reports two SYN and two UDP runs at `f5c75a5`, 10 packets/s for 5 seconds, each
with 50 local sends matching the server capture and zero capture drops. He also
reports Ctrl+C checks for both protocols, reconciled 96-attempt/204-cancelled
records and no sender packets after `stopped_at`, plus wrong-target and
bad-interface rejection. These are reported results for that revision; the raw
captures are not in this repository. Higher rates and VM timer stalls were not
covered. His setup-failure finding is addressed by the new terminal record above.

Use this checklist for re-verification and the remaining evaluation review:

1. Agree schema mapping, ports and independent ground truth with Ali; synchronize
   VM clocks and record the source revision and lab configuration.
2. Start a server-side capture with Vince. Run each protocol twice with identical
   settings; retain four independent UUID directories and the matching captures.
3. Verify the captured destination/source, TCP SYN flag or UDP protocol, IPv4
   lengths and timestamps. Compare local successful/uncertain sends against
   captured packets, documenting capture loss and host-generated responses.
4. Check requested versus achieved load, summary equations and JSON/CSV identities.
   A timer-stalled run is not evidence of the requested rate.
5. Interrupt each protocol during a run, verify exit 130 and reconciled files,
   then verify no further scenario sends in the capture. Also check unreachable
   target and invalid-interface behavior without relaxing the route check.
   Specifically recheck ARP and interface setup failures: exit 2, `state: failed`,
   non-null stop time/error, null scenario start, zero attempts/CSV rows, all
   planned slots cancelled. Retain their UUID directories and code revision.
6. Request team review before marking the Trello task Done. Firewall adapter,
   policy integration and automatic expiry belong to later W3/W4 tasks.

## Automated checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The scenario tests construct/parse packets offline and use mocked senders,
routes and clocks. They cover finite pacing, lag/overrun, cancellation, failed
sends, interruption at the CSV boundary, timestamp/identity consistency,
plan-only behavior, route validation, and setup failure/interruption records.
They also verify that a failed export remains incomplete and that failures after
sending starts never replace real activity with a zero-attempt setup summary.
They do not validate Linux privileges,
actual VM isolation, live socket delivery or repeatability under load.
