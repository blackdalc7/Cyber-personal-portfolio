"""Shared test helpers (importable because pytest adds tests/ to pythonpath)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from realtime_siem.ecs import to_ecs
from realtime_siem.syslog_parser import parse_syslog

FIXTURES = Path(__file__).parent / "fixtures"
BASE = datetime(2026, 10, 26, 11, 0, 0, tzinfo=timezone.utc)


def make_event(msg: str, *, offset_s: float = 0, host: str = "web01", app: str = "sshd", pid: int = 100):
    """Build an ECS event exactly as the pipeline would from an RFC 5424 datagram."""
    ts = (BASE + timedelta(seconds=offset_s)).isoformat().replace("+00:00", "Z")
    raw = f"<86>1 {ts} {host} {app} {pid} - - {msg}"
    return to_ecs(parse_syslog(raw.encode(), received_at=BASE + timedelta(seconds=offset_s)))


def failed(user: str, ip: str, offset_s: float = 0, **kw):
    return make_event(f"Failed password for {user} from {ip} port 4242 ssh2", offset_s=offset_s, **kw)


def accepted(user: str, ip: str, offset_s: float = 0, **kw):
    return make_event(f"Accepted password for {user} from {ip} port 4242 ssh2", offset_s=offset_s, **kw)
