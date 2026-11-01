"""Offline chat provider: writes the exact Slack Block Kit payloads to disk.

Used for demos and CI where no Slack workspace exists. Approvals are then sent
with ``scripts/simulate_click.py``, which signs a genuine Slack interaction
payload so the real verification path is exercised end to end.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from ..db import Incident
from .slack import build_blocks


class OutboxChat:
    """Offline chat provider that writes each card as a JSON file instead of posting it.

    Used when no Slack or Discord credentials are configured, so the whole flow
    can be demonstrated locally.
    """
    name = "outbox"

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _write(self, incident: Incident, kind: str) -> Path:
        """Write the card for ``incident`` to the next numbered file and return its path."""
        with self._lock:
            n = len(list(self.dir.glob(f"{incident.id}-*.json"))) + 1
            path = self.dir / f"{incident.id}-{n:02d}-{kind}.json"
            path.write_text(json.dumps({"incident_id": incident.id, "status": incident.status,
                                        "blocks": build_blocks(incident)}, indent=2, ensure_ascii=False),
                            encoding="utf-8")
        return path

    def send_approval_request(self, incident: Incident) -> tuple[str, str]:
        """Write the initial approval card. Returns ``("outbox", file_name)``."""
        return "outbox", self._write(incident, "request").name

    def update(self, incident: Incident) -> None:
        """Write a new file with the incident's updated card."""
        self._write(incident, "update")
