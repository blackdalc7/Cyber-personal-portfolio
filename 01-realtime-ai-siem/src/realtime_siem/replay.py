"""Replay a log file to the SIEM over UDP as real syslog datagrams.

Each line is wrapped in a proper syslog header (RFC 5424 by default, or RFC 3164)
so the full parsing path is exercised exactly as it would be by rsyslog,
syslog-ng or a network device.

    python -m realtime_siem.replay tests/fixtures/auth.log --port 5514 --rate 500
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

# auth.log line: "Oct 26 08:01:30 web01 sshd[2055]: message"
_LINE_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$")
AUTHPRIV_INFO = 10 * 8 + 6  # facility authpriv (10), severity informational (6)


def to_datagram(line: str, fmt: str, year: int) -> bytes | None:
    """Wrap one auth.log line in a syslog header.

    Returns ``None`` for blank lines. Lines that do not look like auth.log are sent
    with only a PRI header so the receiver's fallback parser is exercised too.
    """
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = _LINE_RE.match(line)
    if not m:
        return f"<{AUTHPRIV_INFO}>{line}".encode()
    if fmt == "rfc3164":
        return f"<{AUTHPRIV_INFO}>{line}".encode()
    ts = datetime.strptime(f"{year} {m['month']} {int(m['day']):02d} {m['time']}", "%Y %b %d %H:%M:%S")
    stamp = ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    return (f"<{AUTHPRIV_INFO}>1 {stamp} {m['host']} {m['tag']} {m['pid'] or '-'} - - "
            f"\ufeff{m['msg']}").encode()


def iter_datagrams(path: Path, fmt: str, year: int) -> Iterator[bytes]:
    """Yield one syslog datagram per non-blank line of ``path``."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            dgram = to_datagram(line, fmt, year)
            if dgram:
                yield dgram


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: send every line of a file to a UDP syslog receiver at a fixed rate."""
    ap = argparse.ArgumentParser(description="Replay a log file to a UDP syslog receiver.")
    ap.add_argument("file", type=Path)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--format", choices=["rfc5424", "rfc3164"], default="rfc5424")
    ap.add_argument("--year", type=int, default=datetime.now(timezone.utc).year)
    ap.add_argument("--rate", type=float, default=200.0, help="datagrams per second (0 = unthrottled)")
    args = ap.parse_args(argv)
    if not args.file.is_file():
        print(f"error: {args.file} not found", file=sys.stderr)
        return 2
    sent = 0
    delay = 1.0 / args.rate if args.rate > 0 else 0.0
    with socket.socket(socket.AF_INET6 if ":" in args.host else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for dgram in iter_datagrams(args.file, args.format, args.year):
            sock.sendto(dgram, (args.host, args.port))
            sent += 1
            if delay:
                time.sleep(delay)
    print(f"sent {sent} datagrams to udp://{args.host}:{args.port} ({args.format})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
