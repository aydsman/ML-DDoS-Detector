#!/usr/bin/env bash
# Shared helpers for monitor-start.sh and monitor-stop.sh. Source it; do not run it.
#
# The state file (monitor.pid) holds two numbers: the process id and that
# process's start time in clock ticks (field 22 of /proc/<pid>/stat). A pid alone
# cannot tell the monitor from an unrelated process that reused the number, so
# a process only counts as "our monitor" when the pid, the start time and the
# command line (python -m ddos_detector.monitor) all match.

[ -r /proc/self/stat ] || { echo "error: these scripts need Linux /proc" >&2; exit 2; }

# Start time of a pid in clock ticks; empty if the process does not exist.
proc_start_ticks() {
  local stat
  stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  # The command name (field 2) may contain spaces and parentheses; cut after the last ")".
  stat="${stat##*) }"
  set -- $stat
  echo "${20}"
}

# True if the pid exists and is not a zombie. kill -0 succeeds on a zombie (an
# exited child that has not been reaped), so it cannot be used to see that the
# monitor died.
proc_running() {
  local stat
  stat="$(cat "/proc/$1/stat" 2>/dev/null)" || return 1
  stat="${stat##*) }"
  [ "${stat%% *}" != "Z" ]
}

# Reads $PID_FILE into STATE_PID and STATE_START. Returns 1 if the file is missing
# and 3 if its contents are not exactly "<pid> <start ticks>".
read_state() {
  STATE_PID=""; STATE_START=""
  [ -f "$PID_FILE" ] || return 1
  local line
  line="$(cat "$PID_FILE")" || return 3
  if [[ ! "$line" =~ ^([1-9][0-9]*)[[:blank:]]+([0-9]+)$ ]]; then
    return 3
  fi
  STATE_PID="${BASH_REMATCH[1]}"
  STATE_START="${BASH_REMATCH[2]}"
}

# True only if STATE_PID is alive, started when recorded, and runs the monitor module.
state_is_our_monitor() {
  local now cmdline
  now="$(proc_start_ticks "$STATE_PID")" || return 1
  [ "$now" = "$STATE_START" ] || return 1
  cmdline="$(tr '\0' ' ' < "/proc/$STATE_PID/cmdline" 2>/dev/null)" || return 1
  case "$cmdline" in *ddos_detector.monitor*) return 0 ;; *) return 1 ;; esac
}

# True if any process currently has the recorded pid (used only for messages).
pid_exists() { [ -d "/proc/$1" ]; }

# Last line of the log, or nothing.
last_record() { tail -n 1 "$1" 2>/dev/null || true; }

record_is_completed() {
  case "$1" in
    *'"record_type": "monitor_status"'*'"status": "completed"'*) return 0 ;;
    *) return 1 ;;
  esac
}

record_is_started() {
  case "$1" in
    *'"record_type": "monitor_status"'*'"status": "started"'*) return 0 ;;
    *) return 1 ;;
  esac
}

# Serialize start and stop. Fd 9 holds the lock; the monitor itself must be
# launched with 9>&- so it does not keep the lock for its whole run.
take_lock() {
  command -v flock >/dev/null || { echo "error: flock is required (package util-linux)" >&2; exit 2; }
  mkdir -p "$MONITOR_LOG_DIR"
  exec 9>"$MONITOR_LOG_DIR/monitor.lock"
  flock -w "${MONITOR_LOCK_WAIT:-10}" 9 || { echo "error: another monitor-start or monitor-stop is running" >&2; exit 1; }
}
