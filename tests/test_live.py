import json
import random
import socket
import struct
from pathlib import Path

import pytest

from ddos_detector import capture
from ddos_detector.config import Config
from ddos_detector.live import CaptureGap, LivePipeline, main
from ddos_detector.offline import extract_pcap, record_row
from ddos_detector.pcap import PcapError, read_pcap
from test_frames import eth, ipv4
from test_pcap import build_pcap

LAB_PCAPS = sorted((Path(__file__).resolve().parent.parent / "data/lab-runs").glob("*/*.pcap"))


def synthetic_pcap(tmp_path, n=300, seed=3):
    rng = random.Random(seed)
    frames = []
    for ts in sorted(rng.uniform(50, 62) for _ in range(n)):
        kind = rng.randrange(6)
        if kind == 0:
            frame = eth(0x0806, bytes(28))
        elif kind == 1:
            frame = eth(0x0800, ipv4(dst="10.10.10.99"))
        elif kind == 2:
            frame = eth(0x0800, ipv4(proto=17, total_length=rng.randrange(28, 400),
                                     src=f"10.10.10.{rng.randrange(20, 60)}"))
        else:
            frame = eth(0x0800, ipv4(src=f"10.10.10.{rng.randrange(20, 60)}",
                                     flags=rng.choice([0x02, 0x12, 0x10, 0x04])))
        frames.append((ts, frame))
    return build_pcap(tmp_path / "s.pcap", records=frames)


def replay(frames, config=Config(), ticks=False, **kw):
    """Run frames through a LivePipeline; return (records, pipeline)."""
    latest = [0.0]
    pipeline = LivePipeline(config, clock=lambda: latest[0], **kw)

    def source():
        for ts, frame in frames:
            latest[0] = max(latest[0], ts)
            yield ts, frame
            if ticks:
                yield None  # idle timeout: the pipeline ticks the (simulated) clock

    return list(pipeline.run(source())), pipeline


def shuffled_within_grace(frames, seed):
    """Deliver sorted frames out of order inside batches spanning < 0.5 s."""
    rng, out, batch = random.Random(seed), [], []
    for item in frames:
        if batch and item[0] - batch[0][0] >= 0.5:
            rng.shuffle(batch)
            out += batch
            batch = []
        batch.append(item)
    rng.shuffle(batch)
    return out + batch


def assert_parity(path):
    offline, off_skips = extract_pcap(path)
    frames = list(read_pcap(path))
    for variant in (frames, shuffled_within_grace(frames, 1)):
        for ticks in (False, True):
            records, pipeline = replay(variant, ticks=ticks)
            assert records == offline
            assert pipeline.skips == off_skips
            assert pipeline.late_dropped == 0 and pipeline.status == "ok"
            assert [record_row(r) for r in records] == [record_row(r) for r in offline]


def test_parity_on_synthetic_pcap(tmp_path):
    path = synthetic_pcap(tmp_path)
    assert len(extract_pcap(path)[0]) >= 10
    assert_parity(path)


@pytest.mark.parametrize("pcap", LAB_PCAPS, ids=lambda p: p.name)
def test_parity_on_lab_pcap(pcap):
    assert_parity(pcap)


def test_parity_with_small_cap_flags(tmp_path):
    config = Config(max_sources_per_window=4)
    path = synthetic_pcap(tmp_path)
    offline, _ = extract_pcap(path, config)
    records, _ = replay(list(read_pcap(path)), config)
    assert records == offline and any(r.capped for r in records)


def test_deterministic(tmp_path):
    frames = list(read_pcap(synthetic_pcap(tmp_path)))
    assert replay(frames)[0] == replay(frames)[0]


def test_capture_failure_is_unavailable_not_zero(tmp_path):
    path = synthetic_pcap(tmp_path)
    frames = list(read_pcap(path))
    pipeline = LivePipeline()

    def source():
        yield from frames[:len(frames) // 2]
        raise RuntimeError("interface went down")

    records = list(pipeline.run(source()))
    offline, _ = extract_pcap(path)
    assert pipeline.status == "unavailable"
    (gap,) = pipeline.gaps
    assert isinstance(gap, CaptureGap) and "interface went down" in gap.reason
    assert gap.discarded_windows >= 1 and gap.since is not None
    assert records == offline[:len(records)]  # only fully finalized windows, nothing synthesized
    assert all(r.packet_count > 0 for r in records)
    assert len(records) < len(offline)
    assert pipeline.flush() == [] and pipeline.tick(1e9) == []
    with pytest.raises(RuntimeError):
        pipeline.feed(*frames[0])


def test_bad_pcap_in_replay_is_an_error_not_a_gap(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00" * 40)
    pipeline = LivePipeline()
    with pytest.raises(PcapError, match="bad magic"):
        list(pipeline.run(read_pcap(bad)))
    assert pipeline.status == "ok"


def test_tick_closes_windows_on_a_quiet_link():
    pipeline = LivePipeline()
    assert pipeline.feed(100.5, eth(0x0800, ipv4())) == []
    assert pipeline.tick(101.9) == []
    (record,) = pipeline.tick(102.0)
    assert (record.window_start, record.packet_count) == (100.0, 1)
    assert pipeline.tick(500.0) == []  # a quiet link emits nothing by default


def test_tick_zero_fills_only_with_emit_empty():
    pipeline = LivePipeline(emit_empty=True)
    pipeline.feed(100.5, eth(0x0800, ipv4()))
    out = pipeline.tick(102.0) + pipeline.tick(104.0)
    assert [(r.window_start, r.packet_count) for r in out] == [(100.0, 1), (101.0, 0), (102.0, 0)]


def test_tick_uses_injected_clock():
    now = [100.0]
    pipeline = LivePipeline(clock=lambda: now[0])
    pipeline.feed(100.5, eth(0x0800, ipv4()))
    assert pipeline.tick() == []
    now[0] = 102.0
    assert len(pipeline.tick()) == 1


def test_late_packets_are_dropped_and_counted():
    pipeline = LivePipeline()
    frame = eth(0x0800, ipv4())
    pipeline.feed(0.5, frame)
    pipeline.feed(5.0, frame)
    assert pipeline.feed(0.6, frame) == []
    assert pipeline.late_dropped == 1


def test_stop_finalizes_ended_windows_and_drops_the_partial_one():
    pipeline = LivePipeline()
    frame = eth(0x0800, ipv4())
    pipeline.feed(10.2, frame)
    pipeline.feed(11.7, frame)
    records = pipeline.stop(11.9)
    assert [r.window_start for r in records] == [10.0]
    assert pipeline.partial_windows_discarded == 1


def test_cli_replay_matches_offline_output(tmp_path, capsys):
    path = synthetic_pcap(tmp_path)
    out = tmp_path / "live.jsonl"
    assert main(["--replay", str(path), "--out", str(out)]) == 0
    summary = capsys.readouterr().out
    assert "status: ok" in summary and "late_dropped: 0" in summary
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert rows == [record_row(r) for r in extract_pcap(path)[0]]


def test_cli_replay_csv_and_no_output_file_by_default(tmp_path):
    path = synthetic_pcap(tmp_path)
    before = set(tmp_path.iterdir())
    assert main(["--replay", str(path)]) == 0
    assert set(tmp_path.iterdir()) == before
    assert main(["--replay", str(path), "--out", str(tmp_path / "r.csv")]) == 0
    assert (tmp_path / "r.csv").read_text().startswith("window_start,window_end,packet_rate")


def test_cli_errors(tmp_path, capsys, monkeypatch):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x00" * 40)
    assert main(["--replay", str(bad)]) == 2
    with pytest.raises(SystemExit):
        main([])
    with pytest.raises(SystemExit):
        main(["--replay", str(bad), "--interface", "eth0"])
    monkeypatch.setattr(capture.sys, "platform", "win32")
    assert main(["--interface", "eth0"]) == 2
    assert "Linux" in capsys.readouterr().err


def test_capture_import_is_safe_and_refuses_off_linux(monkeypatch):
    monkeypatch.setattr(capture.sys, "platform", "win32")
    with pytest.raises(NotImplementedError, match="Linux"):
        capture.capture_frames("eth0")


def test_capture_without_privileges_gives_clear_error(monkeypatch):
    monkeypatch.setattr(capture.sys, "platform", "linux")
    monkeypatch.setattr(socket, "AF_PACKET", 17, raising=False)

    def deny(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(socket, "socket", deny)
    with pytest.raises(PermissionError, match="CAP_NET_RAW"):
        capture.capture_frames("eth0")


def test_capture_timestamp_parsing():
    data = struct.pack("@ll", 1700000000, 500000000)
    assert capture._timestamp([(socket.SOL_SOCKET, capture.SO_TIMESTAMPNS, data)]) == 1700000000.5
    assert capture._timestamp([]) > 1e9  # falls back to the wall clock


def test_filtered_frames_advance_time_and_close_windows():
    pipeline = LivePipeline()
    assert pipeline.feed(100.5, eth(0x0800, ipv4())) == []
    assert pipeline.feed(101.0, eth(0x0806, bytes(28))) == []  # ARP
    assert pipeline.feed(101.999, eth(0x0800, ipv4(dst="10.10.10.99"))) == []  # other destination
    (record,) = pipeline.feed(102.0, eth(0x0806, bytes(28)))
    assert (record.window_start, record.packet_count) == (100.0, 1)


def test_window_closes_during_continuous_unselected_traffic():
    # The source never goes idle (no None timeouts), so only filtered frames move time.
    pipeline = LivePipeline()
    records = list(pipeline.feed(100.5, eth(0x0800, ipv4())))
    for i in range(10):
        records += pipeline.feed(101.0 + i * 0.5, eth(0x0806, bytes(28)))
    assert [(r.window_start, r.packet_count) for r in records] == [(100.0, 1)]


def test_packet_late_after_a_filtered_frame_is_dropped_and_counted():
    pipeline = LivePipeline()
    pipeline.feed(100.5, eth(0x0800, ipv4()))
    pipeline.feed(102.0, eth(0x0806, bytes(28)))  # closes window 100
    assert pipeline.feed(100.7, eth(0x0800, ipv4())) == []
    assert pipeline.late_dropped == 1


def test_offline_and_live_agree_when_filtered_frames_close_windows(tmp_path):
    frames = [(100.5, eth(0x0800, ipv4())), (102.0, eth(0x0806, bytes(28))),
              (100.7, eth(0x0800, ipv4()))]
    path = build_pcap(tmp_path / "late.pcap", records=frames)
    offline, _ = extract_pcap(path)
    live, pipeline = replay(frames)
    assert offline == live and pipeline.late_dropped == 1


def test_kernel_stats_are_read_from_packet_statistics():
    class Sock:
        def getsockopt(self, level, name, size):
            assert (level, name) == (capture.SOL_PACKET, capture.PACKET_STATISTICS)
            return struct.pack("@II", 1200, 7)

    assert capture.read_kernel_stats(Sock()) == (1200, 7)


def test_kernel_stats_unreadable_is_none_not_zero():
    class Sock:
        def getsockopt(self, *args):
            raise OSError("not a packet socket")

    assert capture.read_kernel_stats(Sock()) is None


def test_capture_stats_accumulate_and_start_unknown():
    stats = capture.CaptureStats()
    assert stats.packets is None and stats.drops is None
    stats.add(10, 1)
    stats.add(5, 0)
    assert (stats.packets, stats.drops) == (15, 1)


def test_frames_generator_reads_counters_when_closed():
    class Sock:
        closed = False

        def recvmsg(self, *args):
            raise TimeoutError

        def getsockopt(self, *args):
            return struct.pack("@II", 50, 3)

        def close(self):
            self.closed = True

    stats, sock = capture.CaptureStats(), Sock()
    frames = capture._frames(sock, None, stats)
    assert next(frames) is None
    frames.close()
    assert (stats.packets, stats.drops) == (50, 3) and sock.closed
