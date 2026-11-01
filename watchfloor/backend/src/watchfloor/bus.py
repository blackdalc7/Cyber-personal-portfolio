"""Redis Streams transport for OCSF events.

Producers ``XADD`` one entry per event (field ``e`` holds the JSON); the lake writer
reads through a consumer group so a restart resumes where it stopped, and the hub
reads with plain ``XREAD`` for live fan-out to browsers. Invalid documents never reach
the main stream: they go to a dead-letter stream with the reason.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from . import ocsf

logger = logging.getLogger("watchfloor.bus")


class EventBus:
    """Thin wrapper around a ``redis.Redis`` client (or ``fakeredis`` in tests)."""

    def __init__(self, client: Any, stream: str = "wf:events", dead_letter: str = "wf:dead",
                 maxlen: int = 200_000) -> None:
        self.r = client
        self.stream = stream
        self.dead_letter = dead_letter
        self.maxlen = maxlen

    @classmethod
    def from_url(cls, url: str, **kw: Any) -> EventBus:
        """Connect to Redis at ``url`` (``redis://host:port/db``)."""
        import redis  # imported lazily so mappers and the lake can be used without Redis installed

        return cls(redis.Redis.from_url(url, decode_responses=True), **kw)

    def publish(self, doc: dict[str, Any], *, validate: bool = True) -> str | None:
        """Validate and append one event; returns the stream id, or ``None`` if it was dead-lettered."""
        if validate:
            try:
                ocsf.validate(doc)
            except ocsf.ContractError as exc:
                self.r.xadd(self.dead_letter, {"reason": str(exc)[:2000], "e": json.dumps(doc, default=str)[:65536]},
                            maxlen=10_000, approximate=True)
                logger.warning("Dead-lettered event: %s", exc)
                return None
        payload = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)
        return self.r.xadd(self.stream, {"e": payload}, maxlen=self.maxlen, approximate=True)

    def publish_many(self, docs: Iterable[dict[str, Any]], *, validate: bool = True) -> int:
        """Publish several events through one pipeline; returns how many were accepted."""
        pipe = self.r.pipeline(transaction=False)
        accepted = 0
        for doc in docs:
            if validate:
                try:
                    ocsf.validate(doc)
                except ocsf.ContractError as exc:
                    pipe.xadd(self.dead_letter, {"reason": str(exc)[:2000], "e": json.dumps(doc, default=str)[:65536]},
                              maxlen=10_000, approximate=True)
                    continue
            pipe.xadd(self.stream, {"e": json.dumps(doc, separators=(",", ":"), ensure_ascii=False)},
                      maxlen=self.maxlen, approximate=True)
            accepted += 1
        pipe.execute()
        return accepted

    def ensure_group(self, group: str) -> None:
        """Create consumer group ``group`` at the start of the stream if it does not exist."""
        try:
            self.r.xgroup_create(self.stream, group, id="0", mkstream=True)
        except Exception as exc:  # redis raises ResponseError("BUSYGROUP ...") when it already exists
            if "BUSYGROUP" not in str(exc):
                raise

    def read_group(self, group: str, consumer: str, count: int = 500, block_ms: int = 1000
                   ) -> list[tuple[str, dict[str, Any]]]:
        """Read new entries for ``consumer``; returns ``(entry_id, event)`` pairs."""
        resp = self.r.xreadgroup(group, consumer, {self.stream: ">"}, count=count, block=block_ms)
        return self._decode(resp)

    def ack(self, group: str, ids: list[str]) -> None:
        """Acknowledge processed entries so they are not redelivered."""
        if ids:
            self.r.xack(self.stream, group, *ids)

    def read_after(self, last_id: str = "$", count: int = 200, block_ms: int = 15000
                   ) -> list[tuple[str, dict[str, Any]]]:
        """Plain ``XREAD`` after ``last_id`` (``$`` = only new entries); used for live fan-out."""
        resp = self.r.xread({self.stream: last_id}, count=count, block=block_ms)
        return self._decode(resp)

    def dead_letters(self, count: int = 50) -> list[dict[str, Any]]:
        """Return the most recent dead-lettered entries (newest first)."""
        return [{"id": i, **f} for i, f in self.r.xrevrange(self.dead_letter, count=count)]

    @staticmethod
    def _decode(resp: Any) -> list[tuple[str, dict[str, Any]]]:
        out = []
        for _stream, entries in resp or []:
            for entry_id, fields in entries:
                raw = fields.get("e") if isinstance(fields, dict) else None
                if raw is None:
                    continue
                try:
                    out.append((entry_id, json.loads(raw)))
                except ValueError:
                    logger.error("Undecodable stream entry %s", entry_id)
        return out
