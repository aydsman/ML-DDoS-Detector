"""Linux AF_PACKET frame source for live capture (stdlib only).

Importing this module is safe on any platform; capture_frames() raises
NotImplementedError off Linux and PermissionError without root/CAP_NET_RAW.
"""
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
SO_TIMESTAMPNS = 35  # Linux value; the socket module does not export it
MAX_FRAME = 65535


def capture_frames(interface, timeout=0.5, duration=None):
    """Return a generator of (ts, frame) from interface, with None after each idle timeout.

    ts is the kernel receive timestamp (SO_TIMESTAMPNS, epoch seconds) and
    falls back to time.time() at receive if the kernel supplies none. The None
    items let LivePipeline.run tick the clock on a quiet link. The generator
    ends after duration seconds (wall clock) if given. Frames in both
    directions are returned; the frame parser keeps only inbound IPv4.
    """
    if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
        raise NotImplementedError("live capture needs Linux (AF_PACKET); use --replay elsewhere")
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
            sock.bind((interface, 0))
        except OSError:
            sock.close()
            raise
    except PermissionError as exc:
        raise PermissionError("AF_PACKET capture needs root or CAP_NET_RAW") from exc
    sock.settimeout(timeout)
    return _frames(sock, duration)


def _frames(sock, duration):
    deadline = None if duration is None else time.monotonic() + duration
    try:
        while deadline is None or time.monotonic() < deadline:
            try:
                frame, ancillary, _, _ = sock.recvmsg(MAX_FRAME, 128)
            except (socket.timeout, TimeoutError):
                yield None
                continue
            yield _timestamp(ancillary), frame
    finally:
        sock.close()


def _timestamp(ancillary):
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            try:
                sec, nsec = struct.unpack("@ll", data[:struct.calcsize("@ll")])
                return sec + nsec / 1e9
            except struct.error:
                break
    return time.time()
