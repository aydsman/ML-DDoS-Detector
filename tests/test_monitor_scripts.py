"""Offline checks for scripts/monitor-start.sh and scripts/monitor-stop.sh.

The functional test replaces the Python interpreter with a small shell stub, so
it needs no root, no network interface and no model. Skipped where bash is missing.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
START = ROOT / "scripts" / "monitor-start.sh"
STOP = ROOT / "scripts" / "monitor-stop.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not available")


def posix(path):
    return Path(path).as_posix()


def write_config(tmp_path, **overrides):
    values = {"MONITOR_INTERFACE": "enp0s8", "MONITOR_FORBIDDEN_INTERFACE": "enp0s3",
              "MONITOR_VICTIM": "10.10.10.10", "MONITOR_MODEL": posix(tmp_path / "model"),
              "MONITOR_PYTHON": "python3", "MONITOR_LOG_DIR": posix(tmp_path / "logs"),
              "MONITOR_DURATION": ""}
    values.update(overrides)
    config = tmp_path / "monitor.env"
    config.write_text("".join(f"{key}={value}\n" for key, value in values.items()),
                      encoding="utf-8", newline="\n")
    return config


def run(script, config, *args, **env):
    full_env = {**os.environ, "MONITOR_CONFIG": posix(config), **env}
    return subprocess.run([BASH, posix(script), *args], capture_output=True, text=True,
                          env=full_env, timeout=60)


def test_dry_run_prints_the_command_and_starts_nothing(tmp_path):
    config = write_config(tmp_path, MONITOR_DURATION="100")
    result = run(START, config, "--dry-run")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "--interface enp0s8" in out and "--victim 10.10.10.10" in out
    assert "--window 1" in out and "--duration 100" in out
    assert posix(tmp_path / "model") in out and posix(tmp_path / "logs") in out
    assert not (tmp_path / "logs").exists()


def test_missing_config_is_reported(tmp_path):
    result = run(START, tmp_path / "absent.env")
    assert result.returncode == 2 and "config not found" in result.stderr


@pytest.mark.parametrize("override, message", [
    ({"MONITOR_INTERFACE": ""}, "MONITOR_INTERFACE is required"),
    ({"MONITOR_MODEL": ""}, "MONITOR_MODEL is required"),
    ({"MONITOR_INTERFACE": "enp0s3"}, "management NIC"),
    ({"MONITOR_DURATION": "-5"}, "MONITOR_DURATION"),
    ({"MONITOR_DURATION": "abc"}, "MONITOR_DURATION"),
])
def test_bad_settings_are_refused_before_anything_starts(tmp_path, override, message):
    result = run(START, write_config(tmp_path, **override), "--dry-run")
    assert result.returncode == 2 and message in result.stderr
    assert not (tmp_path / "logs").exists()


def test_unknown_option_is_refused(tmp_path):
    assert run(START, write_config(tmp_path), "--now").returncode == 2


def test_stop_without_a_pid_file_says_not_running(tmp_path):
    result = run(STOP, write_config(tmp_path))
    assert result.returncode == 0 and "not running" in result.stdout


STUB = """#!/usr/bin/env bash
while [ $# -gt 0 ]; do
  if [ "$1" = "--log" ]; then LOG="$2"; fi
  shift
done
echo '{"record_type": "monitor_status", "status": "started"}' > "$LOG"
on_int() {
  echo '{"record_type": "monitor_status", "status": "completed"}' >> "$LOG"
  exit 0
}
trap on_int TERM
while true; do sleep 0.2; done
"""


@pytest.mark.skipif(sys.platform.startswith("win"), reason="needs POSIX signals")
def test_start_then_stop_ends_with_a_completed_record(tmp_path):
    stub = tmp_path / "fake-python.sh"
    stub.write_text(STUB, encoding="utf-8", newline="\n")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "model").mkdir()
    config = write_config(tmp_path, MONITOR_PYTHON=posix(stub))
    env = {"MONITOR_SKIP_HOST_CHECKS": "1", "MONITOR_STOP_WAIT": "10"}

    started = run(START, config, **env)
    assert started.returncode == 0, started.stderr
    pid_file = tmp_path / "logs" / "monitor.pid"
    assert pid_file.exists()
    again = run(START, config, **env)
    assert again.returncode == 2 and "already running" in again.stderr

    stopped = run(STOP, config, **env)
    assert stopped.returncode == 0, stopped.stderr + stopped.stdout
    assert "stopped cleanly" in stopped.stdout and not pid_file.exists()
    log = Path((tmp_path / "logs" / "monitor.current-log").read_text().strip())
    assert json.loads(log.read_text().splitlines()[-1])["status"] == "completed"
    assert "not running" in run(STOP, config, **env).stdout
