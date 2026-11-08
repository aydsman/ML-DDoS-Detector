"""Review real producer-format records offline; no HTTP or scenario traffic."""

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json

import pytest
from scapy.layers.inet import IP, UDP

from ddos_detector import scenarios
from ddos_detector.http_client import (
    ClientSettings, RequestResult, RunResult, RunSettings, export_run,
)
from tools import review_measurements as review


BASE = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def stamp(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


def http_export(tmp_path, observations=None, *, interrupted=False):
    """Use the real finalizer with coherent, explicitly synthetic observations."""
    if observations is None:
        observations = [('http_response', 200, None, 10),
                        ('http_response', 204, None, 20),
                        ('http_response', 503, None, 1000),
                        ('timeout', None, 'ReadTimeout', 2000),
                        ('request_error', None, 'ConnectError', 3000)]
    requests = [RequestResult(stamp(i), ms, outcome, status, error, i + 1)
                for i, (outcome, status, error, ms) in enumerate(observations)]
    scheduled = max(1, len(requests)) + (2 if interrupted else 0)
    elapsed = max([1.0, float(scheduled) if not interrupted else 0.0]
                  + [i + request.elapsed_ms / 1000 for i, request in enumerate(requests)])
    result = RunResult(
        started_at=stamp(), elapsed_seconds=elapsed,
        achieved_requests_per_second=len(requests) / elapsed,
        attempted=len(requests),
        successful_2xx=sum(r.status_code is not None and 200 <= r.status_code < 300 for r in requests),
        requests=requests, scheduled_slots=scheduled,
        cancelled_slots=scheduled - len(requests) if interrupted else 0,
        skipped_due_to_lag=0 if interrupted else scheduled - len(requests),
        interrupted=interrupted,
    )
    return export_run(tmp_path, ClientSettings('http://localhost/', 2),
                      RunSettings(1, scheduled), result)


def scenario_export(tmp_path, monkeypatch, protocol='udp', *, outcome='sent', setup=None):
    settings = scenarios.ScenarioSettings(protocol, rate=1, duration=2)
    monkeypatch.setattr(scenarios, 'utc_now', lambda: stamp(10))
    export = scenarios.ScenarioExport(tmp_path, settings)
    try:
        if setup is not None:
            export.finish_setup_failure(settings, setup)
        else:
            export.metadata['started_at'] = stamp()
            packet = IP(bytes(scenarios.build_packet(settings, 1)))
            errors = {'sent': None, 'send_error': 'OSError',
                      'interrupted_unknown': 'KeyboardInterrupt', 'unknown': None}
            rows = [{
                'packet_index': 1, 'started_at': stamp(1),
                'epoch_seconds': (BASE + timedelta(seconds=1)).timestamp(),
                'elapsed_ms': 1.5, 'ip_bytes': packet.len,
                'outcome': outcome, 'error_type': errors[outcome],
            }]
            interrupted = outcome in {'unknown', 'interrupted_unknown'}
            state = 'complete' if outcome == 'sent' else 'interrupted' if interrupted else 'failed'
            summary = {
                'scheduled_slots': 2, 'attempted': 1, 'sent': int(outcome == 'sent'),
                'send_errors': int(outcome == 'send_error'), 'unknown': int(interrupted),
                'skipped_due_to_lag': int(state == 'complete'),
                'cancelled_slots': int(state != 'complete'), 'elapsed_seconds': 2.0,
                'achieved_packets_per_second': 0.5 if outcome == 'sent' else 0.0,
                'interrupted': interrupted,
            }
            export.finish(rows, summary, state)
    finally:
        export.close()
    return export.directory


def change_meta(directory, change):
    path = directory / 'run.json'
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data))


def change_rows(directory, change, filename='requests.csv'):
    path = directory / filename
    with path.open(newline='') as handle:
        reader = csv.DictReader(handle)
        fields, rows = reader.fieldnames, list(reader)
    change(rows)
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def assert_invalid(directory):
    result = review.review_export(directory)
    assert not result['valid'], result
    assert result['problems']
    assert result['metrics'] is None
    assert not result['full_duration_trial']
    return result


def test_http_success_and_failure_durations_are_not_mixed(tmp_path):
    directory = http_export(tmp_path)
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    result = review.review_export(directory)
    assert result['valid'], result['problems']
    assert result['full_duration_trial']
    metrics = result['metrics']
    assert metrics['success_predicate_id'] == 'http_get_status_2xx_v1'
    assert metrics['attempted'] == 5
    assert metrics['success_rate'] == pytest.approx(0.4)
    assert metrics['outcomes'] == {'success': 2, 'invalid_response': 1, 'timeout': 1,
                                   'transport_error': 1, 'unknown': 0}
    latency = metrics['successful_latency_seconds']
    assert (latency['n'], latency['p50'], latency['p95'], latency['p99']) == (2, .01, .02, .02)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    for artifact in result['artifacts']:
        assert artifact['sha256'] == hashlib.sha256(before[artifact['path']]).hexdigest()


def test_percentiles_use_nearest_rank_and_report_sample_count(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, n) for n in range(1, 21)])
    metrics = review.review_export(directory)['metrics']['successful_latency_seconds']
    assert metrics['method'] == 'nearest_rank'
    assert metrics['n'] == 20
    assert (metrics['p50'], metrics['p95'], metrics['p99']) == (.010, .019, .020)


@pytest.mark.parametrize('raw,error,interrupted', [
    ('unexpected_error', 'RuntimeError', False), ('interrupted', 'KeyboardInterrupt', True),
])
def test_unknown_results_keep_attempt_denominator_and_bounds(tmp_path, raw, error, interrupted):
    directory = http_export(tmp_path, [('http_response', 200, None, 10),
                                      (raw, None, error, 9000)], interrupted=interrupted)
    result = review.review_export(directory)
    assert result['valid'], result['problems']
    metrics = result['metrics']
    assert metrics['attempted'] == 2
    assert metrics['success_rate'] is None
    assert metrics['success_rate_bounds'] == [.5, 1.0]
    assert metrics['unavailable_reason'] == 'unknown_outcomes'
    assert metrics['successful_latency_seconds']['n'] == 1
    assert metrics['successful_latency_seconds']['p99'] == .01
    if interrupted:
        assert not result['full_duration_trial']


def test_zero_attempts_are_not_perfect_success_or_a_baseline(tmp_path):
    result = review.review_export(http_export(tmp_path, []))
    assert result['valid'], result['problems']
    assert not result['full_duration_trial']
    assert result['metrics']['success_rate'] is None
    assert result['metrics']['success_rate_bounds'] is None
    assert result['metrics']['successful_latency_seconds']['p50'] is None


def test_known_failures_have_zero_success_but_no_success_latency(tmp_path):
    result = review.review_export(http_export(tmp_path, [('timeout', None, 'ReadTimeout', 5000)]))
    assert result['valid']
    assert result['metrics']['success_rate'] == 0
    assert result['metrics']['successful_latency_seconds']['n'] == 0
    assert result['metrics']['successful_latency_seconds']['p99'] is None


@pytest.mark.parametrize('protocol,expected_ip_bytes', [('syn', 40), ('udp', 49)])
def test_real_scenario_packet_format_is_accepted(tmp_path, monkeypatch, protocol, expected_ip_bytes):
    directory = scenario_export(tmp_path, monkeypatch, protocol)
    result = review.review_export(directory)
    packet = IP(bytes(scenarios.build_packet(scenarios.ScenarioSettings(protocol), 1)))
    assert packet.len == expected_ip_bytes
    if protocol == 'udp':
        assert bytes(packet[UDP].payload) == b'COMP3670 lab scenario'
        assert len(bytes(packet[UDP].payload)) == 21
    assert result['valid'], result['problems']
    assert result['metrics']['server_received'] is None
    assert result['metrics']['scope'] == 'local_sender_only'
    assert 'successful_latency_seconds' not in result['metrics']


@pytest.mark.parametrize('outcome', ['send_error', 'interrupted_unknown', 'unknown'])
def test_scenario_terminal_uncertain_or_failed_sends_are_not_complete_trials(tmp_path, monkeypatch, outcome):
    result = review.review_export(scenario_export(tmp_path, monkeypatch, 'syn', outcome=outcome))
    assert result['valid'], result['problems']
    assert not result['full_duration_trial']
    assert result['metrics']['attempted'] == 1
    assert result['metrics']['sent'] == 0
    assert result['metrics']['server_received'] is None


@pytest.mark.parametrize('error', [ValueError('No ARP answer'), KeyboardInterrupt()])
def test_real_setup_failure_exports_are_not_measured_zero_traffic(tmp_path, monkeypatch, error):
    result = review.review_export(scenario_export(tmp_path, monkeypatch, setup=error))
    assert result['valid'], result['problems']
    assert not result['full_duration_trial']
    assert result['workload']['attempted'] == 0
    assert result['workload']['cancelled_slots'] == 2
    assert result['metrics']['server_received'] is None


@pytest.mark.parametrize('field,value', [
    ('request_index', '0'), ('request_index', '99'),
    ('run_id', '00000000-0000-0000-0000-000000000000'),
    ('epoch_seconds', '1'), ('elapsed_ms', 'nan'), ('elapsed_ms', 'Infinity'),
    ('elapsed_ms', '-1'), ('elapsed_ms', ''), ('elapsed_ms', 'not-a-number'),
    ('started_at', '2026-11-04T12:00:00'), ('started_at', '2026-11-04T12:00:00+00:00'),
    ('outcome', 'made_up'), ('status_code', ''), ('status_code', '999'),
    ('error_type', 'UnexpectedError'),
])
def test_malformed_http_rows_do_not_produce_metrics(tmp_path, field, value):
    directory = http_export(tmp_path)
    change_rows(directory, lambda rows: rows[0].update({field: value}))
    assert_invalid(directory)


def test_duplicate_indices_are_rejected_even_when_counts_still_match(tmp_path):
    directory = http_export(tmp_path)
    change_rows(directory, lambda rows: rows[1].update(request_index=rows[0]['request_index']))
    assert_invalid(directory)


def test_utc_before_run_start_is_rejected_with_consistent_epoch(tmp_path):
    directory = http_export(tmp_path)
    change_rows(directory, lambda rows: rows[0].update(
        started_at=stamp(-1), epoch_seconds=str((BASE - timedelta(seconds=1)).timestamp())))
    assert_invalid(directory)


def test_http_export_initialization_delay_does_not_create_a_false_end_bound(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)])
    change_rows(directory, lambda rows: rows[0].update(
        started_at=stamp(100), epoch_seconds=str((BASE + timedelta(seconds=100)).timestamp())))
    result = review.review_export(directory)
    assert result['valid'], result['problems']
    assert result['timestamp_alignment'] == 'passed'


@pytest.mark.parametrize('change', [
    lambda m: m.update(state='running', summary=None),
    lambda m: m.update(state='unexpected_state'),
    lambda m: m.update(summary=None),
    lambda m: m.update(traffic_type='controlled_syn'),
    lambda m: m.update(schema_version='draft-1'),
    lambda m: m['summary'].update(attempted=999),
    lambda m: m['summary'].update(successful_2xx=5),
    lambda m: m['summary'].update(scheduled_slots=999),
    lambda m: m['summary'].update(cancelled_slots=1),
    lambda m: m['summary'].update(attempted=True),
    lambda m: m['summary'].update(elapsed_seconds=0),
    lambda m: m['summary'].update(achieved_requests_per_second=999),
    lambda m: m['summary'].update(interrupted=True),
    lambda m: m['summary'].update(outcome_counts={'http_response': 5}),
    lambda m: m['summary'].pop('scheduled_slots'),
    lambda m: m['summary'].pop('cancelled_slots'),
])
def test_unfinished_inconsistent_and_older_ledger_exports_are_explicitly_invalid(tmp_path, change):
    directory = http_export(tmp_path)
    change_meta(directory, change)
    assert_invalid(directory)


@pytest.mark.parametrize('damage', ['duplicate_header', 'partial_header', 'short_row', 'extra_field'])
def test_csv_shape_errors_are_not_silently_ignored(tmp_path, damage):
    directory = http_export(tmp_path)
    path = directory / 'requests.csv'
    rows = list(csv.reader(io.StringIO(path.read_text())))
    if damage == 'duplicate_header':
        rows[0][-1] = rows[0][0]
    elif damage == 'partial_header':
        rows[0] = rows[0][:-1]
    elif damage == 'short_row':
        rows[1] = rows[1][:-1]
    else:
        rows[1].append('extra')
    with path.open('w', newline='') as handle:
        csv.writer(handle).writerows(rows)
    assert_invalid(directory)


def test_duplicate_json_keys_are_rejected_not_resolved_by_last_value(tmp_path):
    directory = http_export(tmp_path)
    path = directory / 'run.json'
    # The final value is valid: a permissive decoder silently hides the conflict.
    raw = path.read_text()
    path.write_text('{"state":"running",' + raw[1:])
    assert_invalid(directory)


def test_boolean_outcome_count_is_not_an_integer_measurement(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)])
    change_meta(directory, lambda meta: meta['summary'].update(outcome_counts={'http_response': True}))
    assert_invalid(directory)


def test_nonfinite_json_constant_is_rejected(tmp_path):
    directory = http_export(tmp_path)
    path = directory / 'run.json'
    meta = json.loads(path.read_text())
    meta['summary']['elapsed_seconds'] = float('nan')
    path.write_text(json.dumps(meta))
    assert_invalid(directory)


@pytest.mark.parametrize('damage', ['stop_before_start', 'row_after_stop', 'wrong_ip_bytes'])
def test_scenario_bounds_and_packet_lengths_are_checked(tmp_path, monkeypatch, damage):
    directory = scenario_export(tmp_path, monkeypatch, 'syn')
    if damage == 'stop_before_start':
        change_meta(directory, lambda meta: meta.update(stopped_at=stamp(-1)))
    elif damage == 'row_after_stop':
        change_rows(directory, lambda rows: rows[0].update(
            started_at=stamp(11), epoch_seconds=str((BASE + timedelta(seconds=11)).timestamp())), 'activity.csv')
    else:
        change_rows(directory, lambda rows: rows[0].update(ip_bytes=39), 'activity.csv')
    assert_invalid(directory)


@pytest.mark.parametrize('filename', ['run.json', 'requests.csv'])
def test_missing_source_files_return_invalid_without_crashing(tmp_path, filename):
    directory = http_export(tmp_path)
    (directory / filename).unlink()
    assert_invalid(directory)


def test_cli_rejects_duplicate_component_uuid(tmp_path, capsys):
    directory = http_export(tmp_path)
    assert review.main([str(directory), str(directory)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert not report['valid']
    assert report['problems'] == ['duplicate component run UUIDs']


def test_cli_reports_missing_directory(tmp_path, capsys):
    assert review.main([str(tmp_path / 'missing')]) == 1
    report = json.loads(capsys.readouterr().out)
    assert not report['valid']
    assert report['runs'][0]['metrics'] is None


def test_cli_records_parent_id_without_rewriting_component_id(tmp_path):
    directory = http_export(tmp_path)
    original = (directory / 'run.json').read_bytes()
    output = tmp_path / 'review.json'
    assert review.main([str(directory), '--experiment-id', 'ali-w2-001', '--output', str(output)]) == 0
    report = json.loads(output.read_text())
    assert report['experiment_id'] == 'ali-w2-001'
    assert report['runs'][0]['run_id'] == json.loads(original)['run_id']
    assert (directory / 'run.json').read_bytes() == original


def test_cli_refuses_to_overwrite_existing_output(tmp_path, capsys):
    directory = http_export(tmp_path)
    output = tmp_path / 'review.json'
    output.write_text('preserve this report')
    assert review.main([str(directory), '--output', str(output)]) == 2
    assert output.read_text() == 'preserve this report'
    assert 'error:' in capsys.readouterr().err


def test_complete_trial_cannot_finish_before_its_requested_window(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)])
    change_meta(directory, lambda meta: meta['summary'].update(
        elapsed_seconds=.05, achieved_requests_per_second=20))
    assert_invalid(directory)


def test_attempt_duration_cannot_exceed_total_observed_run_time(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)])
    change_rows(directory, lambda rows: rows[0].update(elapsed_ms=2000))
    assert_invalid(directory)


def test_complete_response_overrun_is_valid_and_uses_actual_duration(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 3200)])
    result = review.review_export(directory)
    assert result['valid'], result['problems']
    assert result['full_duration_trial']
    assert result['metrics']['successful_latency_seconds']['p95'] == 3.2


def test_reconciled_interruption_may_end_before_configured_duration(tmp_path):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)], interrupted=True)
    change_meta(directory, lambda meta: meta['summary'].update(
        elapsed_seconds=.1, achieved_requests_per_second=10))
    result = review.review_export(directory)
    assert result['valid'], result['problems']
    assert not result['full_duration_trial']


@pytest.mark.parametrize('key,value', [
    ('timeout_seconds', True), ('timeout_seconds', '2'),
    ('request_rate', True), ('request_rate', '1'),
    ('duration_seconds', True), ('duration_seconds', '1'),
    ('concurrency', True), ('concurrency', 1.0),
])
def test_http_settings_require_json_numeric_types_not_booleans_or_strings(tmp_path, key, value):
    directory = http_export(tmp_path, [('http_response', 200, None, 10)])
    change_meta(directory, lambda meta: meta['settings'].update({key: value}))
    assert_invalid(directory)


@pytest.mark.parametrize('key,value', [('rate', True), ('rate', '1'), ('interface', 42)])
def test_scenario_setting_type_errors_return_invalid_instead_of_crashing(tmp_path, monkeypatch, key, value):
    directory = scenario_export(tmp_path, monkeypatch, 'syn')
    change_meta(directory, lambda meta: meta['settings'].update({key: value}))
    assert_invalid(directory)
