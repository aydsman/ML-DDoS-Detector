# Re-recording S1 and S2 (issue #49)

The original S1/S2 captures were lost in the November 21 host reset. This runbook re-records both sessions on the rebuilt lab with the original schedule. It is waiting on Ayden's answer on #49 about whether the re-recordings replace the originals or count as new sessions. The steps are the same either way. S3 is not re-recorded.

**Where the schedule comes from.** The coverage files in `lab-handoff.zip`, attached to #3 (SHA-256 `691e9887…`, the archive Ayden reviewed):

| | Original S1 / S2 |
| --- | --- |
| Benign client | HTTP from 10.10.10.20, 20 requests/s for 930 s (18,600 / 18,596 attempted), started with the capture |
| Benign lead | 6 min before the first attack run |
| Attack runs | 6 runs from 10.10.10.30, 160 packets/s for 60 s each, starting about 91 s apart, in the order SYN, UDP, SYN, UDP, SYN, UDP |
| Capture | Server `enp0s8`, about 15.5 min, 931 one-second windows, 0 dropped |
| Labeling | Attacker packets inside a run (including RSTs) are attack. A window is attack only at 80% or more attack share. Boundary slack is 2.5 s. |
| Windows (attack / benign / excluded) | S1: 253 / 527 / 151. S2: 250 / 528 / 153 |

The labeler used then, `tools/lab_join.py`, was never committed. `tools/lab_session_export.py` rebuilds its rules and adds the per-source counts #49 needs.

Two scripts do the work:
- `tools/lab_s1s2_attacks.sh` runs on the attacker and does the run timing, so nobody has to time runs by hand.
- `tools/lab_session_export.py` runs on the host afterwards.

## 0. Before the session (NAT on, SSH allowed)

**One-time setup on the client and attacker.** The clones were made before the repository was installed on the server, so they need the same setup as the server (uv 0.13.10, Python 3.12.16, `requirements.txt`):

```bash
curl -LsSf https://astral.sh/uv/0.13.10/install.sh | sh
git clone https://github.com/aydsman/ML-DDoS-Detector.git ~/ML-DDoS-Detector && cd ~/ML-DDoS-Detector
~/.local/bin/uv venv --python 3.12.16 .venv && ~/.local/bin/uv pip install --python .venv/bin/python -r requirements.txt
~/.local/bin/uv pip check --python .venv/bin/python && .venv/bin/python -m pytest -q
```

**Timing gate.** The VMs have to keep the schedule, or the windows won't be comparable with the originals. This check runs the real schedulers at the session rates and sends nothing:

```bash
.venv/bin/python -m tools.lab_timing_check --role attacker   # on the attacker: needs >= 92.9% of slots
.venv/bin/python -m tools.lab_timing_check --role client     # on the client: needs >= 98% of slots
```

Don't record if either check fails. On November 27 both failed on this host. A 10 pps rehearsal delivered 44–58% of SYN slots and 62% of client requests, because VirtualBox fell back to running on Hyper-V (`VBox.log`: "VT-x is not available ... fall back to NEM") while Windows virtualization-based security was on. Fix the host first, then run the gate again.

From the host, on all three VMs (`ssh -p 2222/2223/2224 lab@127.0.0.1`):

```bash
cd ~/ML-DDoS-Detector && git fetch && git checkout <revision> && git rev-parse HEAD   # same commit on all three
timedatectl | grep -E "synchronized|NTP"                                              # expect "yes"
df -h ~ | tail -1                                                                      # a few hundred MB free is enough
```

Record the clock offsets against the server. In host PowerShell, run this three times and keep the middle result:

```powershell
foreach ($p in 2222,2223,2224) { ssh -p $p lab@127.0.0.1 date +%s.%N }
```

Check that every VM still has its `baseline-2026-11-26` snapshot (`& $vb snapshot ddos-server list`, and the same for the client and attacker).

On the attacker, preview the schedule. This sends nothing and doesn't wait:

```bash
cd ~/ML-DDoS-Detector && tools/lab_s1s2_attacks.sh S1 --preview
```

## 1. Turn NAT off

```powershell
& $vb controlvm ddos-server setlinkstate1 off
& $vb controlvm ddos-client setlinkstate1 off
& $vb controlvm ddos-attacker setlinkstate1 off
```

From here on, use the VirtualBox console windows. SSH is gone.

## 2. Run one session (replace S1 with S2 for the second)

Use three consoles, in this order.

**Server**, starting the capture first:

```bash
mkdir -p ~/rerec/S1 && sudo tcpdump -i enp0s8 -nn -w ~/rerec/S1/server.pcap
```

**Client**, starting the benign load:

```bash
cd ~/ML-DDoS-Detector && ./.venv/bin/python -m ddos_detector.http_client --target http://10.10.10.10/ --rate 20 --duration 930 --output results/rerec-S1/client
```

**Attacker**, started right after the client:

```bash
cd ~/ML-DDoS-Detector && sudo tools/lab_s1s2_attacks.sh S1
```

The attack script refuses to start if the attacker's NAT link is up or the session folder isn't empty. It waits 360 s, then runs the six scenarios on the 91 s grid. It logs to `results/rerec-S1/attacks.log` and stops at the first run that doesn't exit 0. The last run ends at about +875 s.

When the client prints its summary (at about +930 s), stop tcpdump with **Ctrl+C**. Write down the `packets dropped by kernel` line. The export needs that number.

If anything fails or is interrupted, keep the files, label the folder as failed, and record the session again from step 2 with a fresh folder (`S1b`). Don't splice runs together.

Reboot all three VMs before S2, as the original sessions did. Use `sudo reboot` at each console and wait about 90 s for the server.

## 3. Turn NAT back on and copy the files out

```powershell
& $vb controlvm ddos-server setlinkstate1 on
& $vb controlvm ddos-client setlinkstate1 on
& $vb controlvm ddos-attacker setlinkstate1 on
```

Repeat the clock check from step 0. If any VM's offset changed by more than 0.5 s, pass the measured offset to the export.

Copy the files to a folder outside the repository, for example `D:\lab-rerec\`. Raw captures stay out of Git.

```powershell
scp -P 2222 -r lab@127.0.0.1:rerec/S1 D:\lab-rerec\S1\server
scp -P 2223 -r lab@127.0.0.1:ML-DDoS-Detector/results/rerec-S1 D:\lab-rerec\S1\client
scp -P 2224 -r lab@127.0.0.1:ML-DDoS-Detector/results/rerec-S1 D:\lab-rerec\S1\attacker
```

Take a new snapshot of each VM (`rerec-S1S2-2026-MM-DD`). Also copy an OVA export to another drive. Snapshots sit on the same disk and would not survive another host reset.

## 4. Export

From the repository root on the host:

```bash
python -m tools.lab_session_export --session S1 \
  --pcap D:/lab-rerec/S1/server/server.pcap \
  --attacker-runs D:/lab-rerec/S1/attacker/scenarios \
  --client-run D:/lab-rerec/S1/client/client/<run-uuid> \
  --tcpdump-dropped 0 --offset-attacker 0 --offset-client 0 \
  --out D:/lab-rerec/S1/export [--model <trusted model folder>]
```

The export folder holds:
- `windows.jsonl`: one row per one-second window with the label or exclusion reason, the 12 features, the per-source/protocol packet and SYN-only counts, and, with `--model` and 0 drops, the model's score at its recorded threshold.
- `manifest.json`: SHA-256 for every input and for `windows.jsonl`, the git revision, Python and library versions, a sent-vs-captured check per run, the label counts, and the original S1/S2 counts for comparison.

Check before handing it over:
- `sent_equals_captured` is true for all six runs.
- `window_packet_count_mismatches` is 0.
- The window counts are close to the originals: about 931 windows, 79 boundary exclusions, and about 250 attack windows.

Attach the two export files to #49. The raw pcap stays on the host and the backup drive.

## Limits

- Labels assume the lab network held only the three VMs.
- Captured-vs-sent matches source and protocol (SYN-only for TCP), not destination port.
- VM clocks run unsynchronised while NAT is off. The 2.5 s slack and boundary exclusions absorb small drift.
- The re-recordings use the same VMs and images as before. They are new captures, not new networks.
