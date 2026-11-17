#!/usr/bin/env bash
# Stop the monitor started by scripts/monitor-start.sh and check its final record.
#
#   sudo scripts/monitor-stop.sh
#
# Sends SIGTERM, which the monitor treats like Ctrl+C: it discards the incomplete
# window and writes its terminal status record. (SIGINT cannot be used, because a
# background job started from a script ignores it.) It never sends SIGKILL,
# because that leaves the log without a terminal record.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${MONITOR_CONFIG:-$ROOT/deploy/monitor.env}"
[ -f "$CONFIG" ] && . "$CONFIG"
MONITOR_LOG_DIR="${MONITOR_LOG_DIR:-$ROOT/results/monitor}"
case "$MONITOR_LOG_DIR" in /*) ;; *) MONITOR_LOG_DIR="$ROOT/$MONITOR_LOG_DIR" ;; esac
PID_FILE="$MONITOR_LOG_DIR/monitor.pid"
CURRENT_FILE="$MONITOR_LOG_DIR/monitor.current-log"
WAIT_SECONDS="${MONITOR_STOP_WAIT:-15}"

if [ ! -f "$PID_FILE" ]; then
  echo "monitor is not running (no pid file in $MONITOR_LOG_DIR)"
  exit 0
fi
PID="$(cat "$PID_FILE")"
if ! kill -0 "$PID" 2>/dev/null; then
  echo "monitor is not running (pid $PID has already exited)"
  rm -f "$PID_FILE"
  exit 0
fi

kill -TERM "$PID" 2>/dev/null || { echo "error: cannot signal pid $PID; try sudo" >&2; exit 1; }
for _ in $(seq 1 "$WAIT_SECONDS"); do
  kill -0 "$PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$PID" 2>/dev/null; then
  echo "error: monitor (pid $PID) is still running after ${WAIT_SECONDS}s; check $MONITOR_LOG_DIR/monitor.stdout" >&2
  exit 1
fi
rm -f "$PID_FILE"

LOG="$(cat "$CURRENT_FILE" 2>/dev/null || true)"
if [ -z "$LOG" ] || [ ! -f "$LOG" ]; then
  echo "monitor stopped, but its log file was not found" >&2
  exit 1
fi
LAST="$(tail -n 1 "$LOG")"
echo "log: $LOG"
echo "final record: $LAST"
case "$LAST" in
  *'"record_type": "monitor_status"'*'"status": "completed"'*) echo "monitor stopped cleanly" ;;
  *) echo "warning: the log does not end with a completed status record; treat it as incomplete" >&2; exit 1 ;;
esac
