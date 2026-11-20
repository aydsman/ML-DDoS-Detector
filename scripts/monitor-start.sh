#!/usr/bin/env bash
# Start the monitor-only pipeline in the background on the lab server.
#
#   sudo scripts/monitor-start.sh [--dry-run]
#
# Settings come from deploy/monitor.env (or the file named by MONITOR_CONFIG).
# See deploy/monitor.env.example. Stop it with scripts/monitor-stop.sh.
# --dry-run prints the command and starts nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/monitor-lib.sh
. "$ROOT/scripts/monitor-lib.sh"
CONFIG="${MONITOR_CONFIG:-$ROOT/deploy/monitor.env}"
DRY_RUN=0
case "${1:-}" in
  "") ;;
  --dry-run) DRY_RUN=1 ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac

fail() { echo "error: $*" >&2; exit 2; }

[ -f "$CONFIG" ] || fail "config not found: $CONFIG (copy deploy/monitor.env.example to deploy/monitor.env)"
# shellcheck disable=SC1090
. "$CONFIG"

MONITOR_INTERFACE="${MONITOR_INTERFACE:-}"
# Unset means the lab management NIC. An empty value is refused below, so the
# check cannot be switched off by accident.
MONITOR_FORBIDDEN_INTERFACE="${MONITOR_FORBIDDEN_INTERFACE-enp0s3}"
MONITOR_ALLOW_ANY_INTERFACE="${MONITOR_ALLOW_ANY_INTERFACE:-0}"
MONITOR_VICTIM="${MONITOR_VICTIM:-10.10.10.10}"
MONITOR_MODEL="${MONITOR_MODEL:-}"
MONITOR_PYTHON="${MONITOR_PYTHON:-python3}"
MONITOR_LOG_DIR="${MONITOR_LOG_DIR:-$ROOT/results/monitor}"
MONITOR_DURATION="${MONITOR_DURATION:-}"
MONITOR_START_WAIT="${MONITOR_START_WAIT:-30}"

[ -n "$MONITOR_INTERFACE" ] || fail "MONITOR_INTERFACE is required"
[ -n "$MONITOR_MODEL" ] || fail "MONITOR_MODEL is required"
if [ -z "$MONITOR_FORBIDDEN_INTERFACE" ] && [ "$MONITOR_ALLOW_ANY_INTERFACE" != 1 ]; then
  fail "MONITOR_FORBIDDEN_INTERFACE is empty; set it to the management NIC (enp0s3), or set MONITOR_ALLOW_ANY_INTERFACE=1 to allow any interface"
fi
if [ -n "$MONITOR_FORBIDDEN_INTERFACE" ] && [ "$MONITOR_INTERFACE" = "$MONITOR_FORBIDDEN_INTERFACE" ]; then
  fail "refusing to monitor $MONITOR_INTERFACE (management NIC); use the lab interface"
fi
if [ -n "$MONITOR_DURATION" ] && ! [[ "$MONITOR_DURATION" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  fail "MONITOR_DURATION must be a positive number of seconds or empty"
fi
[[ "$MONITOR_START_WAIT" =~ ^[1-9][0-9]*$ ]] || fail "MONITOR_START_WAIT must be a whole number of seconds"

# Relative paths in the config are relative to the repository root.
case "$MONITOR_MODEL" in /*) ;; *) MONITOR_MODEL="$ROOT/$MONITOR_MODEL" ;; esac
case "$MONITOR_LOG_DIR" in /*) ;; *) MONITOR_LOG_DIR="$ROOT/$MONITOR_LOG_DIR" ;; esac

PID_FILE="$MONITOR_LOG_DIR/monitor.pid"
CURRENT_FILE="$MONITOR_LOG_DIR/monitor.current-log"
LOG="$MONITOR_LOG_DIR/run-$(date -u +%Y%m%d-%H%M%S).jsonl"

CMD=("$MONITOR_PYTHON" -m ddos_detector.monitor --interface "$MONITOR_INTERFACE"
     --victim "$MONITOR_VICTIM" --window 1 --model "$MONITOR_MODEL" --log "$LOG")
[ -n "$MONITOR_DURATION" ] && CMD+=(--duration "$MONITOR_DURATION")

if [ "$DRY_RUN" = 1 ]; then
  echo "dry run, nothing started"
  echo "PYTHONPATH=$ROOT ${CMD[*]}"
  exit 0
fi

# MONITOR_SKIP_HOST_CHECKS=1 skips the root and interface checks. It exists for
# tests and for replaying on a machine that is not the lab server.
if [ "${MONITOR_SKIP_HOST_CHECKS:-0}" != 1 ]; then
  [ "$(id -u)" = 0 ] || fail "live capture needs root; run with sudo"
  [ -d "/sys/class/net/$MONITOR_INTERFACE" ] || fail "interface $MONITOR_INTERFACE not found (check ip -br a)"
fi
[ -d "$MONITOR_MODEL" ] || fail "model folder not found: $MONITOR_MODEL"

# One start or stop at a time: the "already running" check and the writing of
# the pid file below must not interleave with another start or stop.
take_lock

state_status=0
read_state || state_status=$?
if [ "$state_status" = 3 ]; then
  fail "$PID_FILE is not '<pid> <start time>'; check that no monitor is running (ps), then remove the file"
elif [ "$state_status" = 0 ]; then
  if state_is_our_monitor; then
    fail "monitor already running (pid $STATE_PID); stop it with scripts/monitor-stop.sh"
  fi
  echo "note: removing stale state for pid $STATE_PID (that process is gone or is not the monitor)" >&2
  rm -f "$PID_FILE"
fi

cd "$ROOT"
# 9>&- keeps the monitor from holding the start/stop lock while it runs.
PYTHONPATH="$ROOT" nohup "${CMD[@]}" > "$MONITOR_LOG_DIR/monitor.stdout" 2>&1 9>&- &
PID=$!
START_TICKS="$(proc_start_ticks "$PID" || true)"
if [ -z "$START_TICKS" ] || ! proc_running "$PID"; then
  echo "error: monitor exited right after start; output:" >&2
  cat "$MONITOR_LOG_DIR/monitor.stdout" >&2
  exit 1
fi
echo "$LOG" > "$CURRENT_FILE"
echo "$PID $START_TICKS" > "$PID_FILE.tmp"
mv -f "$PID_FILE.tmp" "$PID_FILE"

# Started means the monitor wrote its own first status record (after the model
# loaded and capture opened), not merely that the process is alive.
waited=0
while :; do
  if [ -f "$LOG" ] && record_is_started "$(head -n 1 "$LOG")"; then
    break
  fi
  if ! proc_running "$PID"; then
    rm -f "$PID_FILE"
    echo "error: monitor exited before writing its first status record; output:" >&2
    cat "$MONITOR_LOG_DIR/monitor.stdout" >&2
    exit 1
  fi
  if [ "$waited" -ge "$((MONITOR_START_WAIT * 2))" ]; then
    echo "error: no first status record in $LOG after ${MONITOR_START_WAIT}s; stopping the monitor" >&2
    kill -TERM "$PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
  fi
  sleep 0.5
  waited=$((waited + 1))
done
echo "monitor started: pid $PID (first status record written)"
echo "log: $LOG"
echo "stop with: scripts/monitor-stop.sh"
