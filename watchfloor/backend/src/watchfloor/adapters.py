"""Adapters that put the existing projects' outputs on the spine without changing them.

* :class:`NdjsonTailer` follows an NDJSON file (01 ``events/alerts/chains.ndjson``,
  03 ``alerts.ndjson``) from a saved byte offset, and copes with rotation.
* :class:`QueueFileWatcher` republishes 06's ``queue.json`` whenever it changes.
* :class:`SoarPoller` polls 02's read API and publishes each incident state change.

Offsets and seen-state are saved to one JSON file so a restart does not re-publish.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from .bus import EventBus
from .mappers import map_record
from .ocsf import ContractError

logger = logging.getLogger("watchfloor.adapters")


class AdapterState:
    """Tiny persistent key/value store (JSON file, atomic replace)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        try:
            self.data: dict[str, Any] = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def get(self, key: str, default: Any = None) -> Any:
        """Return the stored value for ``key``."""
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Store ``value`` and persist immediately."""
        with self._lock:
            self.data[key] = value
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)


class NdjsonTailer:
    """Publish new lines of an NDJSON file, mapped from ``source`` to OCSF."""

    def __init__(self, path: Path, source: str, bus: EventBus, state: AdapterState,
                 mapper: Callable[..., dict[str, Any] | None] = map_record) -> None:
        self.path = Path(path)
        self.source = source
        self.bus = bus
        self.state = state
        self.mapper = mapper
        self.key = f"tail:{self.path}"

    def poll(self) -> int:
        """Publish lines appended since the last poll. Returns events published."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return 0
        saved = self.state.get(self.key, {"ino": None, "offset": 0})
        offset = saved["offset"]
        if saved["ino"] != st.st_ino or st.st_size < offset:
            offset = 0  # rotated or truncated: start the new file from the top
        published = 0
        with self.path.open("rb") as fh:
            fh.seek(offset)
            batch = []
            for raw in fh:
                if not raw.endswith(b"\n"):
                    break  # partial line still being written; pick it up next time
                offset += len(raw)
                line = raw.strip()
                if not line:
                    continue
                try:
                    doc = self.mapper(self.source, json.loads(line))
                except (ValueError, ContractError) as exc:
                    logger.warning("Skipping line in %s: %s", self.path, exc)
                    continue
                if doc is not None:
                    batch.append(doc)
            if batch:
                published = self.bus.publish_many(batch, validate=False)
        self.state.set(self.key, {"ino": st.st_ino, "offset": offset})
        return published


class QueueFileWatcher:
    """Republish 06's triage queue (``queue.json``) whenever its content changes."""

    def __init__(self, path: Path, bus: EventBus, state: AdapterState) -> None:
        self.path = Path(path)
        self.bus = bus
        self.state = state
        self.key = f"queue:{self.path}"

    def poll(self) -> int:
        """Publish every meta-alert in a changed queue file. Returns events published."""
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return 0
        digest = hashlib.sha256(raw).hexdigest()
        if self.state.get(self.key) == digest:
            return 0
        data = json.loads(raw)
        run_time = os.path.getmtime(self.path)
        docs = [map_record("triage", item, run_time=run_time)
                for item in data.get("queue", []) + data.get("suppressed", [])]
        n = self.bus.publish_many([d for d in docs if d], validate=False)
        self.state.set(self.key, digest)
        return n


class SoarPoller:
    """Poll 02's ``GET /incidents`` and publish an Incident Finding per state change."""

    def __init__(self, base_url: str, token: str, bus: EventBus, state: AdapterState,
                 client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.bus = bus
        self.state = state
        self.client = client or httpx.Client(timeout=10, headers={"Authorization": f"Bearer {token}"})

    def poll(self) -> int:
        """Publish incidents whose status changed since the last poll. Returns events published."""
        resp = self.client.get(f"{self.base_url}/incidents", params={"limit": 500})
        resp.raise_for_status()
        seen: dict[str, str] = self.state.get("soar:seen", {})
        docs = []
        for inc in resp.json():
            if seen.get(inc["id"]) == inc.get("status"):
                continue
            docs.append(map_record("soar", inc))
            seen[inc["id"]] = inc.get("status")
        n = self.bus.publish_many([d for d in docs if d], validate=False) if docs else 0
        self.state.set("soar:seen", seen)
        return n
