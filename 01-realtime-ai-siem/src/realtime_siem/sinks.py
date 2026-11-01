"""Disk sinks built on ``logging.handlers.RotatingFileHandler``.

Each stream (events, alerts, chains, app log) gets its own dedicated logger and
rotating file, so a burst of raw events can never push alerts out of retention
and total disk use is capped at ``max_bytes * (backup_count + 1)`` per stream.
Output is NDJSON: one ECS document per line, ready for Filebeat/Elastic Agent,
``jq``, or a bulk loader.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any


class NdjsonSink:
    """Append-only NDJSON file with size-based rotation.

    Args:
        name: stream name; the file is ``<directory>/<name>.ndjson``.
        directory: output directory, created if missing.
        max_bytes: rotate once the active file reaches this size.
        backup_count: number of rotated files to keep.
    """
    def __init__(self, name: str, directory: Path, max_bytes: int, backup_count: int) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f"{name}.ndjson"
        # A unique logger per sink + path so tests and multiple instances never share handlers.
        self._logger = logging.getLogger(f"realtime_siem.sink.{name}.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = logging.handlers.RotatingFileHandler(
            self.path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8", delay=True)
        self._handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._handler)
        self.written = 0

    def write(self, doc: dict[str, Any]) -> None:
        """Serialise ``doc`` as one compact JSON line and append it to the file."""
        self._logger.info(json.dumps(doc, separators=(",", ":"), ensure_ascii=False, default=str))
        self.written += 1

    def flush(self) -> None:
        """Flush buffered lines to disk."""
        self._handler.flush()

    def close(self) -> None:
        """Close the file and detach the handler from its logger."""
        self._handler.close()
        self._logger.removeHandler(self._handler)


def configure_app_logging(directory: Path, max_bytes: int, backup_count: int,
                          level: int = logging.INFO) -> logging.Handler:
    """Send the application's own diagnostics to a rotating file and to stderr."""
    directory.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger("realtime_siem")
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(
        directory / "siem.log", maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")
    file_handler.setFormatter(fmt)
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(file_handler)
    root.addHandler(stream)
    return file_handler
