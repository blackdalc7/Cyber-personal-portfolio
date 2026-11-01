"""Common event shape and format dispatch.

Every event is a dict with Sigma field names (Image, CommandLine, ParentImage, ProcessId,
ParentProcessId, User, CurrentDirectory, Computer) plus private keys:

* ``_logsource``: {"category": "process_creation", "product": "windows" | "linux" | ...}
* ``_time``: timezone-aware datetime of the event
* ``_host``: lower-case host name, used to tie events to an exercise step
* ``_source``: which reader produced it and from which file
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class LogFormatError(ValueError):
    """Raised when a log export cannot be parsed."""


def parse_time(value: Any) -> datetime:
    """Parse a timestamp into an aware UTC datetime.

    Accepts datetimes, ISO 8601 strings with a ``Z`` suffix, and Windows
    SystemTime values with 7 fractional digits.

    Raises:
        LogFormatError: if the value is not a recognisable timestamp.
    """
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        # Windows SystemTime carries 7 fractional digits; Python accepts at most 6.
        if "." in text:
            head, _, tail = text.partition(".")
            # Only the leading run of digits is the fraction; the rest is the UTC offset.
            digits = tail[: len(tail) - len(tail.lstrip("0123456789"))]
            rest = tail[len(digits):]
            text = f"{head}.{digits[:6]}{rest}"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise LogFormatError(f"unparseable timestamp {value!r}") from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_events(path: str | Path, fmt: str = "auto") -> list[dict[str, Any]]:
    """Load a log export into normalised event dicts.

    ``fmt`` is ``ecs`` (NDJSON), ``windows-xml`` (wevtutil export) or ``auto``,
    which sniffs the first bytes of the file.

    Raises:
        LogFormatError: for an unknown format or unparsable content.
    """
    from .ecs import read_ecs_ndjson
    from .winevent import read_windows_xml

    path = Path(path)
    if fmt == "auto":
        head = path.read_text(encoding="utf-8-sig", errors="replace")[:512].lstrip()
        fmt = "windows-xml" if head.startswith("<") else "ecs"
    if fmt == "ecs":
        return read_ecs_ndjson(path)
    if fmt == "windows-xml":
        return read_windows_xml(path)
    raise LogFormatError(f"unknown log format {fmt!r} (use ecs or windows-xml)")
