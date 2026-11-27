# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

COMP-3670 team project (final deadline 2026-12-09): ML detection of SYN/UDP floods on a protected Linux server, temporary firewall blocks, and a local web dashboard. All active work is on `development`; `main` only receives reviewed weekly promotions, so a stale local `main` looks like an empty project. Work is tracked in GitHub issues (the decision and evidence record) and on the Trello board linked in README.md. README.md has the team roles and a repository map. Add new top-level files to that map.

## Commands

Python 3.12 (`.python-version`). Call the venv interpreter directly; don't activate it.

    py -3.12 -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    .\.venv\Scripts\python.exe -m pytest -q                       # full suite (~600 tests), run from repo root
    .\.venv\Scripts\python.exe -m pytest -q tests/test_features.py::test_windows_split
    node --test tests/frontend-api.mjs tests/frontend-validation.mjs tests/frontend-status.mjs tests/frontend-graphs.mjs tests/frontend-refresh.mjs

On Linux use `./.venv/bin/python`. CI (`.github/workflows/ci.yml`, Ubuntu) runs only `pip check` and `pytest -q`. It doesn't run the Node frontend tests. No linter is configured, and dependencies are unpinned. Tests that need real captures, tshark, root or Linux-only features (AF_PACKET, flock, nftables) skip themselves. Skipped is not the same as lab-verified.

Main entry points (`python -m ...`):
- `ddos_detector.offline <pcap> --victim 10.10.10.10 --out records.csv`: features for a saved classic pcap.
- `ddos_detector.live --replay <pcap>` or `--interface enp0s8`: the same pipeline on live frames. Live mode needs Linux and root or CAP_NET_RAW.
- `ddos_detector.monitor --replay|--interface ... --model <dir> --log <new.jsonl>`: monitor-only scoring. Never blocks traffic.
- `ddos_detector.api` (`--replay`, `--interface` or `--audit-log`, `--port`), or `uvicorn ddos_detector.api:app`: dashboard API. Serve the frontend at `/frontend/?source=api`.
- `ddos_detector.training prepare|train|score|final-test`: Random Forest training. See docs/training.md.
- `ddos_detector.scenarios` (attack traffic) and `ddos_detector.http_client` (legitimate client): lab traffic generators.
- `ddos_detector.firewall_cli`: manual scoped block lifecycle.
- `tools.verify_pcap_features <pcap> [--engine scapy]`: independent recomputation of features with tshark or scapy.

## Architecture

Packet path, shared by offline and live: `pcap.py` reads saved captures (`capture.py` reads AF_PACKET frames live) → `frames.py` parses Ethernet frames and selects inbound traffic → `normalize.py` turns IPv4 packets into the shared packet form and counts skip reasons → `aggregate.py` assigns packets to epoch-aligned 1-second windows with bounded state → `features.py` computes the 12 features. `offline.py` and `live.py` are thin drivers around this one path, and `tests/test_live.py` checks they produce identical records. Never write a second extractor. A feature change must update `config.FEATURE_NAMES`, `features.py`, `docs/feature-contract.{md,json}` and `contracts.py` together.

Downstream: `monitor.py` scores finished windows with a saved model package from `training.py` / `training_data.py` and writes append-only JSONL. `api.py` serves a bounded `DashboardStore` from live capture, replay or a recorded audit log to `frontend/`, which is plain JS with no build step. Firewall code is split into a contract, a state journal, an nftables backend and a CLI (`firewall*.py`). The automatic policy-to-firewall runner (`ddos_detector.mitigate`) is in draft PR #47 and isn't on `development` yet. The monitor and API stay monitor-only.

Things that look wrong but are deliberate:
- An unmeasured interval is reported as `unavailable` or as a gap, never as zero traffic. Empty windows aren't written, and a half-finished window is dropped when capture stops.
- Packet size is the IPv4 total length. Only IPv4 packets addressed to the victim count.
- Policy thresholds in `docs/policy-defaults.json` are intentionally `null` until they've been validated against lab evidence (issues #5, #49 and #50). Don't fill them in.
- Keep the leakage rules in `docs/design.md`: no IPs, ports or timestamps as features; split whole runs or sessions, never random windows; fit scalers on training data only. The held-out test session (S3) must not be scored without an approved freeze.

`docs/api-contract.md` is authoritative for the API, and the mock data in `docs/api-examples.json` must change with it.

## Lab and data

The lab is three VirtualBox VMs on an internal network (`docs/lab-setup.md`): ddos-server 10.10.10.10 (capture on `enp0s8`; `enp0s3` is management/NAT and must never be monitored or blocked), ddos-client 10.10.10.20 and ddos-attacker 10.10.10.30. Attack traffic and firewall experiments run only inside this lab. Raw captures, models and run logs go in the gitignored `data/` and `results/` folders. They're shared as hashed ZIPs attached to GitHub issues, never committed.
