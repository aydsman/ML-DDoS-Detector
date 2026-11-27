# Recording new policy lab sessions (issue #49)

**Decision (Ayden, #49, November 27).** The rebuilt lab records *new*, independently identified sessions. They are not replacements for the lost S1/S2. Specifically:
- One **policy-calibration** session to tune candidate source settings.
- One **policy-validation** session to evaluate them.
- Each gets a new session ID (for example `policy-calibration-2026-11-27-a` and `policy-validation-2026-11-27-b`), plus its own session UUID, window IDs, timestamps and input/output hashes.
- The trusted model and its score threshold are used unchanged. No retraining, no S3 scoring, and the original window/manifest files and S3 holdout stay as they are.
- The complete epoch-window sequence is kept, including exclusions and failed or uncertain intervals. Nothing is reduced to a class-balanced subset.
- A failed or partial session is kept as evidence and recorded again under a new ID, never spliced.

If the frozen model behaves poorly on these sessions, that is the result to report. The fresh #51 lab trials validate the combined policy separately.

## What the plan is based on

The session workload follows the original lab pilot, from the coverage files in `lab-handoff.zip` attached to #3 (SHA-256 `691e9887…`). This is **context only**. Reusing the schedule does not reproduce the old packets, and the old window counts are not acceptance targets. Report the rebuilt environment and the workload actually achieved.

| | Plan (from the original pilot) |
| --- | --- |
| Benign client | HTTP from 10.10.10.20, 20 requests/s for 930 s, started with the capture |
| Benign lead | 6 min before the first attack run |
| Attack runs | 6 runs from 10.10.10.30, 160 packets/s for 60 s each, starting 91 s apart, in the order SYN, UDP, SYN, UDP, SYN, UDP |
| Capture | Server `enp0s8`, about 15.5 min |
| Labeling | Attacker packets inside a run (including RSTs) are attack. Windows are excluded first for capture edge, boundary (2.5 s slack plus clock uncertainty), empty, and any unknown label. Only then is a window attack at 80% or more attack share. |
| Historical context | S1: 253 / 527 / 151 attack / benign / excluded windows. S2: 250 / 528 / 153 |

There are three tools:
- `tools/lab_policy_attacks.sh` runs on the attacker. It writes the planned run inventory (`schedule.json`) and times the runs.
- `tools/lab_clock_check.py` runs on the host before and after the session. It records each VM's clock offset with an error bound.
- `tools/lab_session_export.py` runs on the host afterwards. It labels, counts and checks the session, and fails closed when any evidence is missing.

## 0. Before the session (NAT on, SSH allowed)

**One-time setup on the client and attacker** (same as the server: uv 0.13.10, Python 3.12.16, `requirements.txt`):

```bash
curl -LsSf https://astral.sh/uv/0.13.10/install.sh | sh
git clone https://github.com/aydsman/ML-DDoS-Detector.git ~/ML-DDoS-Detector && cd ~/ML-DDoS-Detector
~/.local/bin/uv venv --python 3.12.16 .venv && ~/.local/bin/uv pip install --python .venv/bin/python -r requirements.txt
~/.local/bin/uv pip check --python .venv/bin/python && .venv/bin/python -m pytest -q
```

The trusted model needs exactly numpy 2.5.4, scikit-learn 1.9.1, scipy 1.18.1 and joblib 1.6.0 (`model-requirements.txt` in `week3-model-handoff.zip`). Check `training.versions()` before scoring.

**Timing rehearsal.** This runs the real schedulers at the session rates, against a no-op sender and a mock HTTP transport, and sends nothing:

```bash
.venv/bin/python -m tools.lab_timing_check --role attacker       # on the attacker: needs >= 92.9% of slots
.venv/bin/python -m tools.lab_timing_check --role client         # on the client: needs >= 98% of slots
```

Don't record if either check fails. A pass is only a rehearsal. It doesn't show the real session kept its schedule. The export checks that from the logs and the capture.

**This operator's environment (November 27, Vince's host).** These are records of what one host needed. They are not prerequisites for other teammates. At first both checks failed on this host: a 10 pps rehearsal delivered 44–58% of SYN slots and 62% of client requests. There were two causes:

1. **VirtualBox ran on top of Hyper-V** (`VBox.log`: "VT-x is not available ... fall back to NEM"). Fixed on the Windows host by turning off Memory integrity, running `bcdedit /set hypervisorlaunchtype off`, and setting `DeviceGuard` `EnableVirtualizationBasedSecurity = 0` and `DeviceGuard\Scenarios\WindowsHello` `Enabled = 0`, then rebooting. Check: `VBox.log` "HM: Using VT-x", and Kernel-Boot event 153 "policies: 0 is disabled".
2. **Idle virtual CPUs woke late** (`sleep(5 ms)` took about 8.7 ms). Fixed by booting the client and attacker with `idle=poll` (`GRUB_CMDLINE_LINUX_DEFAULT`; the old file is kept as `/etc/default/grub.before-idle-poll`).

After both fixes the rehearsal gave attacker 98.9–99.1% and client 100%. Snapshot `rerec-ready-2026-11-27` holds that state. A session report should state these host settings as part of the rebuilt environment.

**Check every VM** from the host (`ssh -p 2222/2223/2224 lab@127.0.0.1`):

```bash
cd ~/ML-DDoS-Detector && git fetch && git checkout <revision> && git rev-parse HEAD   # same commit on all three
df -h ~ | tail -1                                                                      # a few hundred MB free is enough
```

**Clock evidence, before.** From the repository root on the host, write to a new session folder outside the repository:

```bash
python -m tools.lab_clock_check --out D:/lab-sessions/<session-id>/clock-before.json
```

Each VM answers repeated `date` requests over one SSH session. The tightest sample gives the offset to the host and a ± bound (half its round trip). A single middle reading of three separate `ssh date` commands is not enough, so don't use one.

On the attacker, preview the plan. This sends nothing and doesn't wait:

```bash
cd ~/ML-DDoS-Detector && tools/lab_policy_attacks.sh <session-id> --preview
```

## 1. Turn NAT off

```powershell
& $vb controlvm ddos-server setlinkstate1 off
& $vb controlvm ddos-client setlinkstate1 off
& $vb controlvm ddos-attacker setlinkstate1 off
```

From here on, use the VirtualBox console windows. SSH is gone.

## 2. Run one session

Use three consoles, in this order. `<session-id>` is new for every attempt.

**Server**, starting the capture first:

```bash
mkdir -p ~/sessions/<session-id> && sudo tcpdump -i enp0s8 -nn -w ~/sessions/<session-id>/server.pcap
```

**Client**, starting the benign load:

```bash
cd ~/ML-DDoS-Detector && ./.venv/bin/python -m ddos_detector.http_client --target http://10.10.10.10/ --rate 20 --duration 930 --output results/<session-id>/client
```

**Attacker**, started right after the client:

```bash
cd ~/ML-DDoS-Detector && sudo tools/lab_policy_attacks.sh <session-id>
```

The attack script refuses to start in three cases: the attacker's NAT link is up, the session ID is malformed, or `results/<session-id>` already exists. It writes `schedule.json`, waits 360 s, runs the six scenarios on the 91 s grid and logs to `attacks.log`. It stops at the first run that doesn't exit 0. The last run ends at about +875 s.

When the client prints its summary (at about +930 s), stop tcpdump with **Ctrl+C**. Write down the `packets dropped by kernel` line.

If anything fails or is interrupted, keep every file and mark the folder as failed. Record again from step 2 under a new ID (for example `...-c`). Failed attempts are evidence. Don't delete them or splice runs together.

Reboot all three VMs between sessions (`sudo reboot` at each console; wait about 90 s for the server).

## 3. Turn NAT back on, check clocks again, copy the files out

```powershell
& $vb controlvm ddos-server setlinkstate1 on
& $vb controlvm ddos-client setlinkstate1 on
& $vb controlvm ddos-attacker setlinkstate1 on
```

**Clock evidence, after**, as soon as SSH works again:

```bash
python -m tools.lab_clock_check --out D:/lab-sessions/<session-id>/clock-after.json
```

The export uses the midpoint of the before and after offsets. Its uncertainty is half their difference plus the larger measurement bound. It widens the boundary exclusions by that uncertainty. If the uncertainty exceeds the 2.5 s slack, the session isn't valid for scoring. A single constant offset is never applied silently.

Copy the files to the session folder outside the repository. Raw captures stay out of Git.

```powershell
scp -P 2222 -r lab@127.0.0.1:sessions/<session-id> D:\lab-sessions\<session-id>\server
scp -P 2223 -r lab@127.0.0.1:ML-DDoS-Detector/results/<session-id> D:\lab-sessions\<session-id>\client
scp -P 2224 -r lab@127.0.0.1:ML-DDoS-Detector/results/<session-id> D:\lab-sessions\<session-id>\attacker
```

**Two verified copies.** Before deleting any working copy on the VMs, copy the whole session folder to a second place that isn't the host disk (USB drive or cloud folder). Compare SHA-256 values file by file:

```powershell
Get-ChildItem -Recurse -File D:\lab-sessions\<session-id> | Get-FileHash -Algorithm SHA256
```

Also take a new snapshot of each VM and export an OVA to the second place. Snapshots sit on the same disk and wouldn't survive another host reset.

## 4. Export

From the repository root on the host:

```bash
python -m tools.lab_session_export --session-id <session-id> \
  --pcap D:/lab-sessions/<session-id>/server/server.pcap \
  --attacker-dir D:/lab-sessions/<session-id>/attacker \
  --client-run D:/lab-sessions/<session-id>/client/client/<run-uuid> \
  --clock-before D:/lab-sessions/<session-id>/clock-before.json \
  --clock-after D:/lab-sessions/<session-id>/clock-after.json \
  --tcpdump-dropped <n> --out D:/lab-sessions/<session-id>/export [--model <trusted model folder>]
```

It exits 0 only when the session is valid for scoring. The export folder holds two files:
- **`windows.jsonl`**: one row for every second from the first to the last captured window. Each row has:
  - the label or exclusion reason, and `eligible_for_policy` with `ineligible_reasons`
  - the 12 features
  - per-source/protocol packet counts, with known-flag, unknown-flag and SYN-only counts
  - with `--model` and a valid session, the trusted model's score

  Ineligible windows (excluded, capped, count mismatch, unknown TCP flags, or an invalid session) must reset policy streaks.
- **`manifest.json`**: the session ID and UUID, `valid_for_scoring` and every problem found, SHA-256 for every input and output, the git revision and library versions, the clock evidence, the schedule, a sent-vs-captured check per run, retained failed runs, the client run, and the label counts.

The checks that make a session invalid:
- The kernel drop count is missing or non-zero.
- The schedule is missing or is for another session.
- There isn't exactly one complete run per scheduled run with the same settings.
- A run is failed or incomplete.
- Log rows don't reconcile with their summaries (run IDs, unique indices, attempted or sent counts).
- The client run isn't complete or doesn't match the planned rate and duration.
- Clock evidence is missing, or its uncertainty is above the slack.
- The capture doesn't cover every run.
- Sent and captured packets differ, or there are packet-count mismatches between the labels and the features.

Zero kernel drops alone never certifies a session.

Attach `manifest.json` and `windows.jsonl` to #49. The raw pcap and logs stay in the two verified copies.

## Limits

- Labels assume the lab network held only the three VMs.
- Captured-vs-sent matches source and protocol (SYN-only for TCP), not destination port.
- VM clocks run unsynchronised while NAT is off. Drift is bounded by the before/after measurements, not measured during the session.
- The sessions use the same VMs and images as before. They are new captures, not new networks.
