"""The lake writer service: Redis Streams consumer group → Parquet.

Entries are acknowledged only after the Parquet file containing them is on disk, so
a crash between read and flush redelivers them instead of losing them (at-least-once;
rows carry the OCSF ``metadata.uid`` so duplicates can be removed at query time).
"""

from __future__ import annotations

import logging
import threading
import time

from .bus import EventBus
from .lake import LakeWriter

logger = logging.getLogger("watchfloor.ingest")

GROUP = "lake-writer"


class IngestService:
    """Consume the event stream and persist it to the lake."""

    def __init__(self, bus: EventBus, writer: LakeWriter, consumer: str = "writer-1",
                 flush_interval_s: float = 5.0, compact_every_s: float = 900.0, clock=time.monotonic) -> None:
        self.bus = bus
        self.writer = writer
        self.consumer = consumer
        self.flush_interval_s = flush_interval_s
        self.compact_every_s = compact_every_s
        self.clock = clock
        self._unacked: list[str] = []
        self._last_flush = clock()
        self._last_compact = clock()
        self._stop = threading.Event()
        self.bus.ensure_group(GROUP)

    def step(self, block_ms: int = 1000) -> int:
        """Read one batch, buffer it and flush/ack when due. Returns entries read."""
        entries = self.bus.read_group(GROUP, self.consumer, block_ms=block_ms)
        for entry_id, doc in entries:
            self.writer.add(doc)
            self._unacked.append(entry_id)
        now = self.clock()
        if self._unacked and (self.writer.pending() == 0 or now - self._last_flush >= self.flush_interval_s):
            self.flush()
        if now - self._last_compact >= self.compact_every_s:
            merged = self.writer.compact()
            if merged:
                logger.info("Compacted %d partitions", merged)
            self._last_compact = now
        return len(entries)

    def flush(self) -> None:
        """Write buffered rows and acknowledge the entries they came from."""
        self.writer.flush()
        self.bus.ack(GROUP, self._unacked)
        self._unacked = []
        self._last_flush = self.clock()

    def run(self) -> None:
        """Loop until :meth:`stop` is called."""
        logger.info("Lake writer consuming %s as %s/%s", self.bus.stream, GROUP, self.consumer)
        while not self._stop.is_set():
            try:
                self.step()
            except Exception:  # keep the service alive; the entry stays pending and is redelivered
                logger.exception("Ingest step failed")
                time.sleep(1)
        self.flush()

    def stop(self) -> None:
        """Ask :meth:`run` to finish after the current step."""
        self._stop.set()
