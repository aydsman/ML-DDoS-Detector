"""Validate current HTTP/scenario exports and calculate client-observed metrics.

Read-only: never sends traffic or changes source artifacts. A valid export is
not proof of packet receipt, synchronized clocks, or a comparable VM baseline.
"""
import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path
import sys
from uuid import UUID

HTTP_FIELDS = {
    'run_id', 'request_index', 'started_at', 'epoch_seconds', 'elapsed_ms',
    'outcome', 'status_code', 'error_type',
}
SCENARIO_FIELDS = (HTTP_FIELDS - {'request_index', 'status_code'}) | {'packet_index', 'ip_bytes'}
TIME_TOLERANCE = 0.000001  # CSV/ISO representations of the same UTC instant.


def _number(value, name, minimum=0):
    if isinstance(value, bool):
        raise ValueError(f'{name} must be numeric')
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be numeric') from None
    if not math.isfinite(number) or number < minimum:
        raise ValueError(f'{name} must be finite and >= {minimum}')
    return number


def _count(value, name):
    number = _number(value, name)
    if number != int(number):
        raise ValueError(f'{name} must be an integer')
    return int(number)


def _utc(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('timestamps must be UTC ISO 8601 ending in Z')
    return datetime.fromisoformat(value).timestamp()


def _uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError('run_id must be a canonical UUID')
    return value


def _strict_json(raw):
    def reject(value):
        raise ValueError(f'non-finite JSON constant: {value}')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f'duplicate JSON key: {key}')
            result[key] = value
        return result
    return json.loads(raw, parse_constant=reject, object_pairs_hook=unique_object)


def _percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def _http_metrics(rows):
    counts = Counter(dict.fromkeys(
        ('success', 'invalid_response', 'timeout', 'transport_error', 'unknown'), 0))
    latencies = []
    for row in rows:
        raw = row['outcome']
        if raw == 'http_response':
            category = 'success' if 200 <= row['status_code'] <= 299 else 'invalid_response'
        elif raw == 'timeout':
            category = 'timeout'
        elif raw == 'request_error':
            category = 'transport_error'
        else:
            category = 'unknown'
        counts[category] += 1
        if category == 'success':
            latencies.append(row['elapsed_ms'] / 1000)
    n, unknown = len(rows), counts['unknown']
    return {
        'scope': 'reconciled_client_attempts_only',
        'success_predicate_id': 'http_get_status_2xx_v1',
        'attempted': n, 'outcomes': dict(counts),
        'success_rate': counts['success'] / n if n and not unknown else None,
        'success_rate_bounds': [counts['success'] / n, (counts['success'] + unknown) / n] if n else None,
        'unavailable_reason': 'zero_denominator' if not n else 'unknown_outcomes' if unknown else None,
        'outcome_rates': {key: value / n if n else None for key, value in counts.items()},
        'successful_latency_seconds': {
            'n': len(latencies), 'method': 'nearest_rank',
            'p50': _percentile(latencies, .5), 'p95': _percentile(latencies, .95),
            'p99': _percentile(latencies, .99),
            'unavailable_reason': None if latencies else 'no_successful_responses',
        },
    }


def review_export(directory):
    """Return a JSON-safe audit. Invalid/incomplete inputs never get metrics."""
    directory = Path(directory)
    result = {
        'schema_version': 'week2-export-review-1', 'run_directory': str(directory.resolve()),
        'run_id': None, 'traffic_type': None, 'state': None, 'valid': False,
        'full_duration_trial': False, 'problems': [], 'artifacts': [],
        'metrics': None, 'timestamp_alignment': 'unavailable',
        'observed_start_windows': [],
        'limitations': [
            'Checks export consistency, not actual server packet receipt or capture coverage.',
            'Generator intent is not a packet/window ground-truth label.',
            'Cross-host clock offsets, uncertainty and VM resource comparability require separate evidence.',
        ],
    }
    problems = result['problems']

    def read(name):
        raw = (directory / name).read_bytes()
        result['artifacts'].append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        return raw

    try:
        meta = _strict_json(read('run.json'))
        if not isinstance(meta, dict):
            raise ValueError('run.json must be an object')
        schema = meta.get('schema_version')
        if schema not in {'draft-2', 'scenario-draft-1'}:
            raise ValueError(f'unsupported schema: {schema!r}')
        http = schema == 'draft-2'
        run_id = _uuid(meta.get('run_id'))
        result.update(run_id=run_id, traffic_type=meta.get('traffic_type'), state=meta.get('state'))
        settings = meta['settings']
        if not isinstance(settings, dict):
            raise ValueError('settings must be an object')
        expected_type = 'legitimate_http' if http else f"controlled_{settings.get('protocol')}"
        if meta.get('traffic_type') != expected_type:
            problems.append('traffic_type does not match schema/protocol')
        # Validate JSON types before calling the producer's settings contract.
        numeric_settings = ('timeout_seconds', 'request_rate', 'duration_seconds') if http else ('rate', 'duration')
        for key in numeric_settings:
            if type(settings.get(key)) not in (int, float):
                raise ValueError(f'settings.{key} must be a JSON number')
        if not http and not isinstance(settings.get('interface'), str):
            raise ValueError('settings.interface must be a string')
        if http:
            from ddos_detector.http_client import ClientSettings, RunSettings
            ClientSettings(settings['target'], settings['timeout_seconds'])
            RunSettings(settings['request_rate'], settings['duration_seconds'], settings['concurrency'])
        else:
            from ddos_detector.scenarios import ScenarioSettings, LAB_SOURCE
            ScenarioSettings(**settings)
            if meta.get('source_ip') != LAB_SOURCE:
                problems.append('scenario source does not match the non-spoofed lab source')
        filename = 'requests.csv' if http else 'activity.csv'
        if meta.get('requests_file' if http else 'activity_file') != filename:
            problems.append('CSV filename does not match the schema')
        reader = csv.DictReader(io.StringIO(read(filename).decode('utf-8-sig'), newline=''))
        expected_fields = HTTP_FIELDS if http else SCENARIO_FIELDS
        if reader.fieldnames is None or set(reader.fieldnames) != expected_fields or len(reader.fieldnames) != len(expected_fields):
            raise ValueError('CSV header has missing, duplicate or unexpected columns')
        raw_rows = list(reader)
        result['observed_rows'] = len(raw_rows)
        state = meta.get('state')
        terminal = {'complete', 'interrupted'} if http else {'complete', 'interrupted', 'failed'}
        summary = meta.get('summary')
        if state not in terminal or not isinstance(summary, dict):
            problems.append('export is unfinished: terminal state and summary required')
            return result
        started = _utc(meta['started_at']) if meta.get('started_at') is not None else None
        stopped = None if http else _utc(meta.get('stopped_at'))
        if started is None and http:
            problems.append('HTTP run start is missing')
        if started is not None and stopped is not None and stopped < started:
            problems.append('scenario stopped_at precedes started_at')
        counter_keys = ['scheduled_slots', 'attempted', 'skipped_due_to_lag', 'cancelled_slots']
        counter_keys += ['skipped_due_to_capacity', 'skipped_at_deadline', 'successful_2xx'] if http else ['sent', 'send_errors', 'unknown']
        for key in counter_keys:
            if type(summary.get(key)) is not int:
                raise ValueError(f'summary.{key} must be a JSON integer; missing legacy counters are unavailable')
        counts = {key: _count(summary.get(key), f'summary.{key}') for key in counter_keys}
        elapsed = _number(summary.get('elapsed_seconds'), 'summary.elapsed_seconds')
        achieved_key = 'achieved_requests_per_second' if http else 'achieved_packets_per_second'
        achieved = _number(summary.get(achieved_key), f'summary.{achieved_key}')
        if type(summary.get('interrupted')) is not bool or summary['interrupted'] != (state == 'interrupted'):
            problems.append('interrupted flag does not match state')
        if state == 'complete' and counts['cancelled_slots']:
            problems.append('complete run cannot contain cancelled slots')
        accounted = counts['attempted'] + counts['skipped_due_to_lag'] + counts['cancelled_slots']
        if http:
            accounted += counts['skipped_due_to_capacity'] + counts['skipped_at_deadline']
        if counts['scheduled_slots'] != accounted:
            problems.append('scheduled-slot ledger does not reconcile')
        rate = settings['request_rate'] if http else settings['rate']
        duration = settings['duration_seconds'] if http else settings['duration']
        if state == 'complete' and elapsed + TIME_TOLERANCE < duration:
            problems.append('complete run elapsed time is shorter than configured duration')
        # A half-open grid is defined by k/rate < duration, including k=0.
        interval = 1 / rate
        expected_slots = math.ceil(duration * rate)
        while expected_slots and (expected_slots - 1) * interval >= duration:
            expected_slots -= 1
        while expected_slots * interval < duration:
            expected_slots += 1
        if counts['scheduled_slots'] != expected_slots:
            problems.append('scheduled_slots does not match configured half-open grid')
        if counts['attempted'] != len(raw_rows):
            problems.append('summary attempt count does not match CSV rows')
        if http and summary.get('started_at') != meta.get('started_at'):
            problems.append('HTTP summary/start metadata disagree')
        if counts['attempted'] and elapsed == 0:
            problems.append('attempts require positive elapsed time')
        numerator = counts['attempted'] if http else counts['sent']
        expected_rate = numerator / elapsed if elapsed else 0
        if not math.isclose(achieved, expected_rate, rel_tol=1e-9, abs_tol=1e-12):
            problems.append('achieved rate does not reconcile with elapsed time and count')
        rows, indices, windows = [], set(), Counter()
        for line, original in enumerate(raw_rows, 2):
            try:
                row = dict(original)
                if None in row or any(value is None for value in row.values()):
                    raise ValueError('CSV row has missing or extra fields')
                if row['run_id'] != run_id:
                    raise ValueError('run_id does not match JSON')
                index = _count(row['request_index' if http else 'packet_index'], 'slot index')
                if not 1 <= index <= counts['scheduled_slots'] or index in indices:
                    raise ValueError('slot index must be unique and within the scheduled grid')
                indices.add(index)
                epoch = _number(row['epoch_seconds'], 'epoch_seconds')
                timestamp = _utc(row['started_at'])
                if abs(timestamp - epoch) > TIME_TOLERANCE:
                    raise ValueError('UTC and epoch timestamps disagree')
                if started is None or timestamp < started - TIME_TOLERANCE:
                    raise ValueError('attempt precedes run start or run start is missing')
                if stopped is not None and timestamp > stopped + TIME_TOLERANCE:
                    raise ValueError('attempt starts after scenario stopped_at')
                # HTTP start is before export setup; no exact scheduling-origin/end
                # UTC is exported. Do not invent one from monotonic elapsed time.
                row['elapsed_ms'] = _number(row['elapsed_ms'], 'elapsed_ms')
                if row['elapsed_ms'] / 1000 > elapsed + TIME_TOLERANCE:
                    raise ValueError('attempt duration exceeds total run elapsed time')
                if http:
                    outcome = row['outcome']
                    if outcome not in {'http_response', 'timeout', 'request_error', 'interrupted', 'unexpected_error'}:
                        raise ValueError('unsupported HTTP outcome')
                    if outcome == 'http_response':
                        row['status_code'] = _count(row['status_code'], 'status_code')
                        if not 100 <= row['status_code'] <= 599 or row['error_type']:
                            raise ValueError('HTTP response needs valid status and no error')
                    elif row['status_code'] or not row['error_type']:
                        raise ValueError('HTTP error needs an exception type and no status')
                else:
                    outcome = row['outcome']
                    if outcome not in {'sent', 'send_error', 'interrupted_unknown', 'unknown'}:
                        raise ValueError('unsupported scenario outcome')
                    expected_bytes = 40 if settings['protocol'] == 'syn' else 49
                    if _count(row['ip_bytes'], 'ip_bytes') != expected_bytes:
                        raise ValueError('IPv4 length does not match generator packet format')
                    if outcome == 'sent' and row['error_type']:
                        raise ValueError('sent row cannot have an error')
                    if outcome in {'send_error', 'interrupted_unknown'} and not row['error_type']:
                        raise ValueError('failed or interrupted send needs an exception type')
                windows[math.floor(epoch)] += 1
                rows.append(row)
            except (ValueError, TypeError, OverflowError) as exc:
                problems.append(f'CSV line {line}: {exc}')
        result['observed_start_windows'] = [
            {'window_start': epoch, 'window_end': epoch + 1, 'attempt_starts': n}
            for epoch, n in sorted(windows.items())
        ]
        outcomes = Counter(row['outcome'] for row in rows)
        if http:
            raw_counts = summary.get('outcome_counts')
            if (not isinstance(raw_counts, dict)
                    or any(type(n) is not int or n < 0 for n in raw_counts.values())
                    or raw_counts != dict(outcomes)):
                problems.append('summary outcome_counts does not match CSV')
            successes = sum(row['outcome'] == 'http_response' and 200 <= row['status_code'] <= 299 for row in rows)
            if counts['successful_2xx'] != successes:
                problems.append('summary successful_2xx does not match CSV')
            result['limitations'].append('HTTP export has no measured scheduling-origin/end/completion UTC; no per-request UTC end is inferred.')
        else:
            expected = {'sent': outcomes['sent'], 'send_errors': outcomes['send_error'],
                        'unknown': outcomes['unknown'] + outcomes['interrupted_unknown']}
            if any(counts[key] != value for key, value in expected.items()):
                problems.append('scenario summary outcomes do not match CSV')
            if started is None:
                error = meta.get('error')
                if (state not in {'failed', 'interrupted'} or not isinstance(error, dict)
                        or error.get('phase') != 'setup' or not error.get('type')
                        or counts['attempted'] or counts['skipped_due_to_lag'] or elapsed
                        or counts['cancelled_slots'] != counts['scheduled_slots']):
                    problems.append('null start requires a reconciled pre-send setup failure/interruption')
            if state == 'complete' and (counts['send_errors'] or counts['unknown']):
                problems.append('complete scenario cannot contain failed/uncertain sends')
        result['valid'] = not problems
        result['timestamp_alignment'] = 'passed' if not problems else 'failed'
        result['full_duration_trial'] = not problems and state == 'complete' and counts['attempted'] > 0
        if not problems:
            result['workload'] = counts
            result['metrics'] = _http_metrics(rows) if http else {
                'scope': 'local_sender_only', 'attempted': counts['attempted'],
                'sent': counts['sent'], 'send_errors': counts['send_errors'],
                'unknown': counts['unknown'], 'server_received': None,
                'unavailable_reason': 'server capture required to establish receipt',
            }
    except (OSError, ValueError, TypeError, KeyError, OverflowError, csv.Error) as exc:
        problems.append(f'cannot validate export: {exc}')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('directories', nargs='+', type=Path)
    parser.add_argument('--experiment-id', help='Explicit parent experiment ID; never rewrites component UUIDs')
    parser.add_argument('--output', type=Path, help='Create a new review JSON (refuses to overwrite)')
    args = parser.parse_args(argv)
    reviews = [review_export(path) for path in args.directories]
    ids = [review['run_id'] for review in reviews if review['run_id']]
    duplicate = len(ids) != len(set(ids))
    report = {'schema_version': 'week2-measurement-review-1', 'experiment_id': args.experiment_id,
              'valid': not duplicate and all(review['valid'] for review in reviews),
              'problems': ['duplicate component run UUIDs'] if duplicate else [], 'runs': reviews}
    output = json.dumps(report, indent=2, allow_nan=False) + '\n'
    if args.output:
        try:
            with args.output.open('x', encoding='utf-8') as handle:
                handle.write(output)
        except OSError as exc:
            print(f'error: {exc}', file=sys.stderr)
            return 2
    else:
        print(output, end='')
    return 0 if report['valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
