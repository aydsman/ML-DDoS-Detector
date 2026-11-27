"""Offline checks for scripts/monitor-start.sh and scripts/monitor-stop.sh.

The functional test replaces the Python interpreter with a small shell stub, so
it needs no root, no network interface and no model. Skipped unless bash, Linux
/proc and flock are all available, because monitor-lib.sh refuses to run without them.
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


def _missing_shell_prerequisite():
    """Return why the scripts cannot run here, or None. Checked through bash itself,
    since bash may see a different filesystem than Python (for example Git Bash)."""
    if BASH is None:
        return "bash is not available"
    probe = subprocess.run(
        [BASH, "-c", "[ -r /proc/self/stat ] || exit 3; command -v flock >/dev/null || exit 4"],
        capture_output=True, timeout=30)
    if probe.returncode == 3:
        return "monitor scripts need Linux /proc (/proc/self/stat is not readable)"
    if probe.returncode == 4:
        return "monitor scripts need flock (util-linux)"
    if probe.returncode != 0:
        return f"bash prerequisite probe failed with exit code {probe.returncode}"
    return None


_MISSING = _missing_shell_prerequisite()
pytestmark = pytest.mark.skipif(_MISSING is not None, reason=_MISSING or "")


def posix(path):
    return Path(path).as_posix()


def write_config(tmp_path, omit=(), **overrides):
    values = {"MONITOR_INTERFACE": "enp0s8", "MONITOR_FORBIDDEN_INTERFACE": "enp0s3",
              "MONITOR_VICTIM": "10.10.10.10", "MONITOR_MODEL": posix(tmp_path / "model"),
              "MONITOR_PYTHON": "python3", "MONITOR_LOG_DIR": posix(tmp_path / "logs"),
              "MONITOR_DURATION": ""}
    values.update(overrides)
    for key in omit:
        values.pop(key)
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


def test_management_nic_is_refused_when_the_setting_is_omitted(tmp_path):
    config = write_config(tmp_path, omit=("MONITOR_FORBIDDEN_INTERFACE",), MONITOR_INTERFACE="enp0s3")
    result = run(START, config, "--dry-run")
    assert result.returncode == 2 and "management NIC" in result.stderr


def test_other_interfaces_pass_when_the_setting_is_omitted(tmp_path):
    config = write_config(tmp_path, omit=("MONITOR_FORBIDDEN_INTERFACE",))
    assert run(START, config, "--dry-run").returncode == 0


def test_empty_forbidden_interface_needs_an_explicit_opt_out(tmp_path):
    config = write_config(tmp_path, MONITOR_FORBIDDEN_INTERFACE="", MONITOR_INTERFACE="enp0s3")
    refused = run(START, config, "--dry-run")
    assert refused.returncode == 2 and "MONITOR_FORBIDDEN_INTERFACE is empty" in refused.stderr
    allowed = run(START, config, "--dry-run", MONITOR_ALLOW_ANY_INTERFACE="1")
    assert allowed.returncode == 0


def test_unknown_option_is_refused(tmp_path):
    assert run(START, write_config(tmp_path), "--now").returncode == 2


@pytest.mark.skipif(shutil.which("flock") is None, reason="monitor stop requires Linux flock")
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


SILENT_STUB = """#!/usr/bin/env bash
on_int() { exit 0; }
trap on_int TERM
while true; do sleep 0.2; done
"""

COMPLETED = '{"record_type": "monitor_status", "status": "completed"}'
posix_only = pytest.mark.skipif(sys.platform.startswith("win"), reason="needs POSIX signals and /proc")


def stub_setup(tmp_path, text=STUB):
    stub = tmp_path / "fake-python.sh"
    stub.write_text(text, encoding="utf-8", newline="\n")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "model").mkdir(exist_ok=True)
    config = write_config(tmp_path, MONITOR_PYTHON=posix(stub))
    env = {"MONITOR_SKIP_HOST_CHECKS": "1", "MONITOR_STOP_WAIT": "10", "MONITOR_LOCK_WAIT": "3"}
    return config, env


def write_state(tmp_path, text, last_record=None):
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    (logs / "monitor.pid").write_text(text, encoding="utf-8")
    if last_record is not None:
        log = logs / "run-old.jsonl"
        log.write_text('{"record_type": "monitor_status", "status": "started"}\n' + last_record + "\n",
                       encoding="utf-8")
        (logs / "monitor.current-log").write_text(str(log) + "\n", encoding="utf-8")


def exited_pid():
    process = subprocess.Popen(["true"])
    process.wait()
    return process.pid


@pytest.fixture
def bystander():
    """An unrelated long-running process that no script may signal."""
    process = subprocess.Popen(["sleep", "60"])
    yield process
    process.kill()
    process.wait()


@posix_only
@pytest.mark.parametrize("content", ["", "abc", "{pid}", "{pid} 456 789", "-5 100", "0 100", "{pid} x", "{pid}\n34 56", "{pid} 1\n34 56"])
def test_stop_rejects_a_malformed_pid_file_without_signalling(tmp_path, bystander, content):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, content.format(pid=bystander.pid))
    result = run(STOP, config, **env)
    assert result.returncode == 1 and "Nothing was signalled" in result.stderr
    assert bystander.poll() is None
    assert (tmp_path / "logs" / "monitor.pid").exists()


@posix_only
def test_stop_does_not_signal_a_process_that_reused_the_pid(tmp_path, bystander):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{bystander.pid} 1\n", COMPLETED)
    result = run(STOP, config, **env)
    assert result.returncode == 0, result.stderr
    assert "different process" in result.stdout and "was not signalled" in result.stdout
    assert bystander.poll() is None
    assert not (tmp_path / "logs" / "monitor.pid").exists()


@posix_only
def test_stop_does_not_signal_when_start_time_matches_but_command_differs(tmp_path, bystander):
    ticks = Path(f"/proc/{bystander.pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{bystander.pid} {ticks}\n", COMPLETED)
    result = run(STOP, config, **env)
    assert result.returncode == 0 and "different process" in result.stdout
    assert bystander.poll() is None


@posix_only
def test_exited_process_with_a_completed_log_is_reported_clean(tmp_path):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{exited_pid()} 1\n", COMPLETED)
    result = run(STOP, config, **env)
    assert result.returncode == 0, result.stderr
    assert "already exited" in result.stdout and "ended cleanly" in result.stdout


@posix_only
@pytest.mark.parametrize("last", ['{"record_type": "window"}',
                                  '{"record_type": "monitor_status", "status": "started"}'])
def test_exited_process_without_a_completed_record_is_not_reported_clean(tmp_path, last):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{exited_pid()} 1\n", last)
    result = run(STOP, config, **env)
    assert result.returncode == 1
    assert "already exited" in result.stdout and "incomplete" in result.stderr
    assert not (tmp_path / "logs" / "monitor.pid").exists()


@posix_only
def test_exited_process_with_no_log_is_reported_as_incomplete(tmp_path):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{exited_pid()} 1\n")
    result = run(STOP, config, **env)
    assert result.returncode == 1 and "log file was not found" in result.stderr


@posix_only
def test_start_replaces_stale_state_and_refuses_malformed_state(tmp_path, bystander):
    config, env = stub_setup(tmp_path)
    write_state(tmp_path, f"{bystander.pid} 1\n")
    started = run(START, config, **env)
    assert started.returncode == 0, started.stderr
    assert "removing stale state" in started.stderr
    assert bystander.poll() is None
    assert run(STOP, config, **env).returncode == 0

    write_state(tmp_path, "garbage")
    refused = run(START, config, **env)
    assert refused.returncode == 2 and "is not '<pid> <start time>'" in refused.stderr


@posix_only
def test_start_is_not_successful_until_the_first_status_record(tmp_path):
    config, env = stub_setup(tmp_path, text=SILENT_STUB)
    result = run(START, config, **{**env, "MONITOR_START_WAIT": "2"})
    assert result.returncode == 1 and "no first status record" in result.stderr
    assert not (tmp_path / "logs" / "monitor.pid").exists()


@posix_only
def test_start_reports_a_monitor_that_exits_before_its_first_record(tmp_path):
    config, env = stub_setup(tmp_path, text="#!/usr/bin/env bash\necho boom >&2\nexit 3\n")
    result = run(START, config, **{**env, "MONITOR_START_WAIT": "5"})
    assert result.returncode == 1 and "boom" in result.stderr
    assert not (tmp_path / "logs" / "monitor.pid").exists()


@posix_only
def test_two_simultaneous_starts_leave_exactly_one_monitor(tmp_path):
    config, env = stub_setup(tmp_path)
    full_env = {**os.environ, "MONITOR_CONFIG": posix(config), **env}
    processes = [subprocess.Popen([BASH, posix(START)], env=full_env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) for _ in range(2)]
    results = []
    for process in processes:
        _, err = process.communicate(timeout=60)
        results.append((process.returncode, err))
    assert sorted(code for code, _ in results) == [0, 2], results
    assert any("already running" in err for _, err in results)
    assert len(list((tmp_path / "logs").glob("run-*.jsonl"))) == 1
    assert run(STOP, config, **env).returncode == 0


@posix_only
def test_the_running_monitor_does_not_hold_the_start_stop_lock(tmp_path):
    config, env = stub_setup(tmp_path)
    assert run(START, config, **env).returncode == 0
    try:
        lock = subprocess.run(["flock", "-n", posix(tmp_path / "logs" / "monitor.lock"), "true"])
        assert lock.returncode == 0
    finally:
        run(STOP, config, **env)


@posix_only
@pytest.mark.parametrize("script, name", [(START, "start"), (STOP, "stop")])
def test_start_and_stop_wait_for_the_lock_and_give_up_when_it_stays_held(tmp_path, script, name):
    config, env = stub_setup(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "monitor.pid").write_text("1 1\n", encoding="utf-8")  # makes stop reach the lock
    holder = subprocess.Popen(["flock", posix(logs / "monitor.lock"), "sleep", "20"])
    try:
        import time
        time.sleep(0.5)  # let the holder take the lock
        result = run(script, config, **{**env, "MONITOR_LOCK_WAIT": "1"})
        assert result.returncode == 1, (name, result.stdout, result.stderr)
        assert "another monitor-start or monitor-stop is running" in result.stderr
        assert not list(logs.glob("run-*.jsonl"))
    finally:
        holder.kill()
        holder.wait()


@posix_only
def test_stop_waits_for_start_lock_even_before_pid_is_published(tmp_path):
    config, env = stub_setup(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    holder = subprocess.Popen(["flock", posix(logs / "monitor.lock"), "sleep", "20"])
    try:
        import time
        time.sleep(0.5)
        result = run(STOP, config, **{**env, "MONITOR_LOCK_WAIT": "1"})
        assert result.returncode == 1
        assert "another monitor-start or monitor-stop" in result.stderr
    finally:
        holder.kill()
        holder.wait()


@posix_only
def test_start_ignores_preceding_run_with_same_clock_second(tmp_path):
    config, env = stub_setup(tmp_path, text=SILENT_STUB)
    bins = tmp_path / "bin"
    bins.mkdir()
    date = bins / "date"
    date.write_text("#!/usr/bin/env bash\necho 20261120-120000\n", newline="\n")
    date.chmod(date.stat().st_mode | stat.S_IXUSR)
    logs = tmp_path / "logs"
    logs.mkdir()
    previous = logs / "run-20261120-120000.jsonl"
    previous.write_text('{"record_type": "monitor_status", "status": "started"}\n')
    result = run(START, config, **{**env, "PATH": str(bins) + os.pathsep + os.environ["PATH"],
                                 "MONITOR_START_WAIT": "1"})
    assert result.returncode == 1 and "no first status record" in result.stderr
    assert previous.read_text().count("started") == 1
