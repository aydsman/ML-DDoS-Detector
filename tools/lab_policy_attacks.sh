#!/usr/bin/env bash
# Attacker-side schedule for one new policy lab session (issue #49 owner decision:
# new policy-calibration / policy-validation sessions, not replacements for S1/S2).
# It uses the original lab pilot's workload (lab-handoff.zip on issue #3) as the
# plan: 6 min benign lead, then six 60 s runs at 160 packets/s, starting every 91 s,
# in the order SYN, UDP, SYN, UDP, SYN, UDP. The old schedule is context only; it
# does not reproduce the old packets.
#
# Start it on the attacker console right after the HTTP client starts on the client VM.
#   sudo tools/lab_policy_attacks.sh policy-calibration-2026-11-27-a            # real session (NAT off)
#   tools/lab_policy_attacks.sh policy-calibration-2026-11-27-a --preview       # plan only, sends nothing
#
# Writes results/<session-id>/schedule.json (the planned run inventory the export
# checks against), scenarios/<run-uuid>/ per run and attacks.log. A failed run
# stops the session; its files are kept as evidence.
set -euo pipefail

session=${1:-}
mode=${2:-}
if ! [[ "$session" =~ ^policy-(calibration|validation)-[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-z0-9]+$ ]]; then
    echo "usage: $0 policy-calibration-YYYY-MM-DD-a|policy-validation-YYYY-MM-DD-b [--preview]" >&2
    exit 2
fi
case "$mode" in ""|--preview) ;; *) echo "unknown option: $mode" >&2; exit 2 ;; esac

cd "$(dirname "$0")/.."
PY=./.venv/bin/python
TARGET=10.10.10.10
IFACE=enp0s8
NAT_IFACE=enp0s3
LEAD=360 RATE=160 DURATION=60 SPACING=91
CLIENT_RATE=20 CLIENT_DURATION=930
PROTOCOLS=(syn udp syn udp syn udp)
DIR=results/$session
OUT=$DIR/scenarios
LOG=$DIR/attacks.log

port_for() { if [ "$1" = syn ]; then echo 80; else echo 9999; fi; }

schedule_json() {
    local runs="" i p
    for i in "${!PROTOCOLS[@]}"; do
        p=${PROTOCOLS[$i]}
        runs+="${runs:+, }{\"index\": $((i + 1)), \"protocol\": \"$p\", \"port\": $(port_for "$p"), \"rate\": $RATE, \"duration\": $DURATION, \"planned_offset_seconds\": $((LEAD + i * SPACING))}"
    done
    printf '{"session_id": "%s", "t0_attacker_epoch": %s, "lead_seconds": %s, "spacing_seconds": %s,\n "client": {"rate": %s, "duration": %s},\n "runs": [%s]}\n' \
        "$session" "$1" "$LEAD" "$SPACING" "$CLIENT_RATE" "$CLIENT_DURATION" "$runs"
}

if [ "$mode" = --preview ]; then
    schedule_json null
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
if [ -e "$DIR" ]; then echo "$DIR already exists; every session needs a new id" >&2; exit 2; fi
mkdir -p "$OUT"

t0=$(date +%s)
schedule_json "$t0" > "$DIR/schedule.json"
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
        echo "run $((i + 1)) exited $status; stopping. Keep these files as a failed session; record again under a new id." | tee -a "$LOG" >&2
        exit "$status"
    fi
done
echo "all 6 runs complete $(date -u +%FT%TZ)" | tee -a "$LOG"
