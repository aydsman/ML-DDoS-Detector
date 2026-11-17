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
MONITOR_FORBIDDEN_INTERFACE="${MONITOR_FORBIDDEN_INTERFACE:-}"
MONITOR_VICTIM="${MONITOR_VICTIM:-10.10.10.10}"
MONITOR_MODEL="${MONITOR_MODEL:-}"
MONITOR_PYTHON="${MONITOR_PYTHON:-python3}"
MONITOR_LOG_DIR="${MONITOR_LOG_DIR:-$ROOT/results/monitor}"
MONITOR_DURATION="${MONITOR_DURATION:-}"

[ -n "$MONITOR_INTERFACE" ] || fail "MONITOR_INTERFACE is required"
[ -n "$MONITOR_MODEL" ] || fail "MONITOR_MODEL is required"
if [ -n "$MONITOR_FORBIDDEN_INTERFACE" ] && [ "$MONITOR_INTERFACE" = "$MONITOR_FORBIDDEN_INTERFACE" ]; then
  fail "refusing to monitor $MONITOR_INTERFACE (management NIC); use the lab interface"
fi
if [ -n "$MONITOR_DURATION" ] && ! [[ "$MONITOR_DURATION" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  fail "MONITOR_DURATION must be a positive number of seconds or empty"
fi

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

mkdir -p "$MONITOR_LOG_DIR"
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  fail "monitor already running (pid $(cat "$PID_FILE")); stop it with scripts/monitor-stop.sh"
fi

cd "$ROOT"
PYTHONPATH="$ROOT" nohup "${CMD[@]}" > "$MONITOR_LOG_DIR/monitor.stdout" 2>&1 &
PID=$!
echo "$PID" > "$PID_FILE"
echo "$LOG" > "$CURRENT_FILE"

sleep 2
if ! kill -0 "$PID" 2>/dev/null; then
  rm -f "$PID_FILE"
  echo "error: monitor exited right after start; output:" >&2
  cat "$MONITOR_LOG_DIR/monitor.stdout" >&2
  exit 1
fi
echo "monitor started: pid $PID"
echo "log: $LOG"
echo "stop with: scripts/monitor-stop.sh"
