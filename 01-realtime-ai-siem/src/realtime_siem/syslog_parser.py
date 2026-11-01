"""Wire-format parsing for syslog datagrams.

Supports the three shapes seen on real networks:

* RFC 5424  ``<34>1 2026-10-26T08:01:30.123Z web01 sshd 2055 - - Accepted ...``
* RFC 3164  ``<38>Oct 26 08:01:30 web01 sshd[2055]: Accepted ...``
* PRI-less BSD lines (what ``logger --udp`` or a raw file replay often sends)

The parser never raises on attacker-controlled input. A datagram it cannot
understand still comes back as a ``SyslogMessage`` with ``format="unknown"`` so
the pipeline can tag it rather than silently drop evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

FACILITY_NAMES = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
    "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
]
SEVERITY_NAMES = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]

# A UTF-8 BOM is allowed (and required by RFC 5424 for UTF-8 MSG) in front of the message.
_BOM = "\ufeff"

_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_HEADER_RE = re.compile(
    r"^(?P<version>[1-9]\d{0,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
)
_RFC3164_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<tag>[^\s:\[]{1,48})(?:\[(?P<pid>[^\]]{1,32})\])?: ?(?P<msg>.*)$",
    re.DOTALL,
)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class SyslogMessage:
    """One parsed syslog message, whatever wire format it arrived in.

    ``format`` records which parser matched: ``rfc5424``, ``rfc3164``, ``bsd``
    (no PRI header) or ``unknown`` (the raw line is kept in ``message``).
    """
    raw: str
    format: str                       # rfc5424 | rfc3164 | bsd | unknown
    message: str
    received_at: datetime
    timestamp: datetime | None = None
    priority: int | None = None
    hostname: str | None = None
    app_name: str | None = None
    procid: str | None = None
    msgid: str | None = None
    version: int | None = None
    structured_data: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def facility(self) -> int | None:
        """Syslog facility number (PRI >> 3), or ``None`` without a PRI header."""
        return None if self.priority is None else self.priority >> 3

    @property
    def severity(self) -> int | None:
        """Syslog severity number (PRI & 7), or ``None`` without a PRI header."""
        return None if self.priority is None else self.priority & 0x07

    @property
    def facility_name(self) -> str | None:
        """Facility keyword such as ``auth`` or ``authpriv``."""
        f = self.facility
        return FACILITY_NAMES[f] if f is not None and f < len(FACILITY_NAMES) else None

    @property
    def severity_name(self) -> str | None:
        """Severity keyword such as ``err`` or ``info``."""
        s = self.severity
        return SEVERITY_NAMES[s] if s is not None else None


def _nil(value: str) -> str | None:
    return None if value == "-" else value


def _resolve_tz(name: str) -> timezone | ZoneInfo:
    if name.upper() in {"UTC", "Z"}:
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def parse_structured_data(text: str) -> tuple[dict[str, dict[str, str]], str]:
    """Parse RFC 5424 STRUCTURED-DATA and return (elements, remaining_message).

    Implemented as a small state machine because SD values may contain escaped
    ``"``, ``\\`` and ``]`` characters, which a regex cannot handle reliably.
    """
    if text.startswith("-"):
        return {}, text[2:] if text.startswith("- ") else text[1:]
    elements: dict[str, dict[str, str]] = {}
    i, n = 0, len(text)
    while i < n and text[i] == "[":
        i += 1
        start = i
        while i < n and text[i] not in " ]":
            i += 1
        sd_id = text[start:i]
        params: dict[str, str] = {}
        while i < n and text[i] == " ":
            i += 1
            start = i
            while i < n and text[i] != "=":
                i += 1
            name = text[start:i]
            i += 1  # '='
            if i >= n or text[i] != '"':
                return elements, text  # malformed: give up on SD, keep raw text as message
            i += 1
            value_chars: list[str] = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n and text[i + 1] in '"\\]':
                    value_chars.append(text[i + 1])
                    i += 2
                    continue
                value_chars.append(text[i])
                i += 1
            i += 1  # closing quote
            params[name] = "".join(value_chars)
        if i >= n or text[i] != "]":
            return elements, text
        i += 1
        if sd_id:
            elements[sd_id] = params
    rest = text[i:]
    return elements, rest[1:] if rest.startswith(" ") else rest


def _parse_5424_timestamp(value: str) -> datetime | None:
    if value == "-":
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _parse_3164_timestamp(month: str, day: str, time_str: str, received_at: datetime,
                          tz: timezone | ZoneInfo) -> datetime | None:
    """BSD syslog omits the year and zone; infer both relative to arrival time."""
    mon = _MONTHS.get(month)
    if mon is None:
        return None
    try:
        hh, mm, ss = (int(x) for x in time_str.split(":"))
        local_now = received_at.astimezone(tz)
        ts = datetime(local_now.year, mon, int(day), hh, mm, ss, tzinfo=tz)
    except ValueError:
        return None
    # A December message received in early January belongs to last year.
    if ts - local_now > timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts.astimezone(timezone.utc)


def parse_syslog(data: bytes | str, received_at: datetime | None = None,
                 default_tz: str = "UTC") -> SyslogMessage:
    """Parse one syslog datagram. Never raises for malformed input."""
    received_at = received_at or datetime.now(timezone.utc)
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    text = text.rstrip("\r\n\x00")
    tz = _resolve_tz(default_tz)

    priority: int | None = None
    body = text
    pri_match = _PRI_RE.match(text)
    if pri_match:
        pri = int(pri_match["pri"])
        if pri <= 191:
            priority = pri
            body = text[pri_match.end():]

    header = _RFC5424_HEADER_RE.match(body)
    if priority is not None and header:
        sd, msg = parse_structured_data(body[header.end():])
        return SyslogMessage(
            raw=text, format="rfc5424", message=msg.lstrip(_BOM), received_at=received_at,
            timestamp=_parse_5424_timestamp(header["ts"]), priority=priority,
            hostname=_nil(header["host"]), app_name=_nil(header["app"]), procid=_nil(header["procid"]),
            msgid=_nil(header["msgid"]), version=int(header["version"]), structured_data=sd,
        )

    bsd = _RFC3164_RE.match(body)
    if bsd:
        return SyslogMessage(
            raw=text, format="rfc3164" if priority is not None else "bsd",
            message=bsd["msg"].lstrip(_BOM), received_at=received_at,
            timestamp=_parse_3164_timestamp(bsd["month"], bsd["day"], bsd["time"], received_at, tz),
            priority=priority, hostname=bsd["host"], app_name=bsd["tag"], procid=bsd["pid"],
        )

    return SyslogMessage(raw=text, format="unknown", message=body.lstrip(_BOM),
                         received_at=received_at, priority=priority)
