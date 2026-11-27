#!/usr/bin/env bash
# Attacker-side schedule for re-recording S1/S2 (issue #49), matching the original
# lab pilot (lab-handoff.zip on issue #3): 6 min benign lead, then six 60 s runs at
# 160 packets/s, starting every 91 s, in the order SYN, UDP, SYN, UDP, SYN, UDP.
#
# Start it on the attacker console right after the HTTP client starts on the client VM.
#   sudo tools/lab_s1s2_attacks.sh S1            # real session (NAT must be off)
#   tools/lab_s1s2_attacks.sh S1 --preview       # print the plan only, no sending, no waiting
set -euo pipefail

session=${1:-}
mode=${2:-}
case "$session" in S1|S2) ;; *) echo "usage: $0 S1|S2 [--preview]" >&2; exit 2 ;; esac
case "$mode" in ""|--preview) ;; *) echo "unknown option: $mode" >&2; exit 2 ;; esac

cd "$(dirname "$0")/.."
PY=./.venv/bin/python
TARGET=10.10.10.10
IFACE=enp0s8
NAT_IFACE=enp0s3
LEAD=360 RATE=160 DURATION=60 SPACING=91
PROTOCOLS=(syn udp syn udp syn udp)
OUT=results/rerec-$session/scenarios
LOG=results/rerec-$session/attacks.log

port_for() { if [ "$1" = syn ]; then echo 80; else echo 9999; fi; }

if [ "$mode" = --preview ]; then
    for i in "${!PROTOCOLS[@]}"; do
        p=${PROTOCOLS[$i]}
        echo "run $((i + 1)): $p at +$((LEAD + i * SPACING)) s"
        "$PY" -m ddos_detector.scenarios --protocol "$p" --target "$TARGET" --interface "$IFACE" \
            --port "$(port_for "$p")" --rate "$RATE" --duration "$DURATION"
    done
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run with sudo (raw sending needs root)" >&2; exit 2; }
# setlinkstate1 off drops the NAT NIC's carrier; reading carrier fails if the link is admin-down.
if [ "$(cat /sys/class/net/$NAT_IFACE/carrier 2>/dev/null || echo 0)" != 0 ]; then
    echo "NAT adapter $NAT_IFACE is up. Turn every NAT adapter off first (docs/lab-setup.md)." >&2
    exit 2
fi
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || { echo "$OUT is not empty; use a fresh session folder" >&2; exit 2; }

t0=$(date +%s)
echo "session $session t0=$t0 ($(date -u +%FT%TZ)); first run at +$LEAD s" | tee -a "$LOG"
for i in "${!PROTOCOLS[@]}"; do
    p=${PROTOCOLS[$i]}
    wait_s=$((t0 + LEAD + i * SPACING - $(date +%s)))
    if [ "$wait_s" -gt 0 ]; then echo "waiting ${wait_s}s for run $((i + 1)) ($p)"; sleep "$wait_s"; fi
    echo "run $((i + 1)) $p start $(date -u +%FT%T.%NZ)" | tee -a "$LOG"
    status=0
    "$PY" -m ddos_detector.scenarios --protocol "$p" --target "$TARGET" --interface "$IFACE" \
        --port "$(port_for "$p")" --rate "$RATE" --duration "$DURATION" --output "$OUT" --execute \
        | tee -a "$LOG" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "run $((i + 1)) exited $status; stopping the session. Do not use it as a complete run." | tee -a "$LOG" >&2
        exit "$status"
    fi
done
echo "all 6 runs complete $(date -u +%FT%TZ)" | tee -a "$LOG"
