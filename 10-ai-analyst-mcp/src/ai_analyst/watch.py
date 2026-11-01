"""Investigate new incidents as they appear, and again when their state changes in 02."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .engine import ProviderError, investigate, transcript_path, write_transcript
from .tools import Toolbox

log = logging.getLogger("ai_analyst.watch")


@dataclass
class Watcher:
    """Investigates new and changed incidents, skipping ones already done and backing off after failures."""
    box: Toolbox
    server: MCPServer
    provider: Any
    out_dir: Path
    max_calls: int = 16
    clock: Callable[[], float] = time.time
    backoff_s: float = 300
    failures: dict[str, tuple[int, float]] = field(default_factory=dict)

    def _done(self, inc: dict[str, Any]) -> bool:
        path = transcript_path(self.out_dir, inc["id"])
        if not path.is_file():
            return False
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return False
        return prev.get("incident_status") == inc["status"]

    def once(self) -> list[Path]:
        """One pass: investigate every incident without a current transcript. Returns the files written."""
        written = []
        now = self.clock()
        for inc in self.box.list_incidents(None, 50)["incidents"]:
            if self._done(inc):
                continue
            count, retry_at = self.failures.get(inc["id"], (0, 0.0))
            if now < retry_at:
                continue
            try:
                doc = investigate(inc["id"], self.box, self.server, self.provider, self.max_calls, now=self.clock)
            except (ProviderError, ToolError) as exc:
                self.failures[inc["id"]] = (count + 1, now + self.backoff_s * 2 ** min(count, 5))
                log.warning("investigation of %s failed (%s); retrying later", inc["id"], exc)
                continue
            doc["incident_status"] = inc["status"]
            self.failures.pop(inc["id"], None)
            written.append(write_transcript(doc, self.out_dir))
            log.info("%s: %s (%.2f), %d tool calls, citations %s", inc["id"], doc["verdict"], doc["confidence"],
                     len(doc["tool_calls"]), "valid" if doc["citations_valid"] else "INVALID")
        return written

    def run(self, interval_s: float, sleep: Callable[[float], None] = time.sleep, cycles: int | None = None) -> None:
        n = 0
        while cycles is None or n < cycles:
            try:
                self.once()
            except Exception:  # keep watching: one bad cycle (lake mid-write, disk full) must not end it
                log.exception("watch cycle failed")
            n += 1
            if cycles is None or n < cycles:
                sleep(interval_s)
