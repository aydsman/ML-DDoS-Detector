#!/usr/bin/env bash
# Stop the monitor started by scripts/monitor-start.sh and check its final record.
#
#   sudo scripts/monitor-stop.sh
#
# Sends SIGTERM, which the monitor treats like Ctrl+C: it discards the incomplete
# window and writes its terminal status record. (SIGINT cannot be used, because a
# background job started from a script ignores it.) It never sends SIGKILL,
# because that leaves the log without a terminal record. It only signals a
# process whose pid, start time and command line match what the start script
# recorded, so a stale or reused pid is never signalled.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/monitor-lib.sh
. "$ROOT/scripts/monitor-lib.sh"
CONFIG="${MONITOR_CONFIG:-$ROOT/deploy/monitor.env}"
[ -f "$CONFIG" ] && . "$CONFIG"
MONITOR_LOG_DIR="${MONITOR_LOG_DIR:-$ROOT/results/monitor}"
case "$MONITOR_LOG_DIR" in /*) ;; *) MONITOR_LOG_DIR="$ROOT/$MONITOR_LOG_DIR" ;; esac
PID_FILE="$MONITOR_LOG_DIR/monitor.pid"
CURRENT_FILE="$MONITOR_LOG_DIR/monitor.current-log"
WAIT_SECONDS="${MONITOR_STOP_WAIT:-15}"

# Wait for an in-progress start before deciding that no monitor exists.
take_lock

# Reports the last record of the current log and exits 0 only if it is a completed status record.
finish_with_log() {
  local log last
  log="$(cat "$CURRENT_FILE" 2>/dev/null || true)"
  if [ -z "$log" ] || [ ! -f "$log" ]; then
    echo "error: the monitor's log file was not found; treat the run as incomplete" >&2
    exit 1
  fi
  last="$(last_record "$log")"
  echo "log: $log"
  echo "final record: $last"
  if record_is_completed "$last"; then
    echo "$1"
    exit 0
  fi
  echo "warning: the log does not end with a completed status record; treat it as incomplete" >&2
  exit 1
}

state_status=0
read_state || state_status=$?
if [ "$state_status" = 1 ]; then
  echo "monitor is not running (no pid file in $MONITOR_LOG_DIR)"
  exit 0
elif [ "$state_status" = 3 ]; then
  echo "error: $PID_FILE is not '<pid> <start time>'. Nothing was signalled. Check ps for a monitor, stop it by hand if one runs, then remove the file." >&2
  exit 1
fi

if ! state_is_our_monitor; then
  if pid_exists "$STATE_PID"; then
    echo "pid $STATE_PID now belongs to a different process; it was not signalled"
  else
    echo "pid $STATE_PID has already exited"
  fi
  rm -f "$PID_FILE"
  finish_with_log "monitor is not running; its last run ended cleanly"
fi

kill -TERM "$STATE_PID" 2>/dev/null || { echo "error: cannot signal pid $STATE_PID; try sudo" >&2; exit 1; }
for _ in $(seq 1 "$WAIT_SECONDS"); do
  state_is_our_monitor || break
  sleep 1
done
if state_is_our_monitor; then
  echo "error: monitor (pid $STATE_PID) is still running after ${WAIT_SECONDS}s; check $MONITOR_LOG_DIR/monitor.stdout" >&2
  exit 1
fi
rm -f "$PID_FILE"
finish_with_log "monitor stopped cleanly"
