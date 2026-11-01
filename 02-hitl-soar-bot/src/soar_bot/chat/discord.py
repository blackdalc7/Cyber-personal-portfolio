"""Discord: message components (buttons), Ed25519 interaction verification, message edits."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..db import Incident
from .base import APPROVE, REJECT, ChatError, action_value, status_line, summary_fields

logger = logging.getLogger("soar_bot.discord")

API = "https://discord.com/api/v10"
SEVERITY_COLOUR = {"low": 0x2ECC71, "medium": 0xF1C40F, "high": 0xE67E22, "critical": 0xE74C3C}

# Interaction types / callback types from the Discord API
PING, COMPONENT = 1, 3
PONG, CHANNEL_MESSAGE, UPDATE_MESSAGE = 1, 4, 7
EPHEMERAL = 1 << 6


def build_message(incident: Incident) -> dict[str, Any]:
    """Build the Discord message (embed plus buttons) for an incident.

    Buttons are only included while the incident awaits approval, and the
    Approve button only when there is a host to isolate.
    """
    embed = {
        "title": f"🚨 {incident.title}"[:256],
        "description": (incident.description or "")[:3000],
        "color": SEVERITY_COLOUR.get(incident.severity, 0x95A5A6),
        "fields": [{"name": k, "value": v[:1024] or "-", "inline": True} for k, v in summary_fields(incident)]
                  + [{"name": "Status", "value": status_line(incident), "inline": False}],
        "footer": {"text": f"Incident {incident.id} · source {incident.source}"},
    }
    components: list[dict[str, Any]] = []
    if incident.status == "awaiting_approval":
        value = action_value(incident)
        buttons = [{"type": 2, "style": 2, "label": "Reject", "custom_id": f"{REJECT}|{value}"}]
        if incident.host:
            buttons.insert(0, {"type": 2, "style": 4, "label": "Approve Isolation", "custom_id": f"{APPROVE}|{value}"})
        components = [{"type": 1, "components": buttons}]
    # allowed_mentions empty: alert content can never ping @everyone or users.
    return {"embeds": [embed], "components": components, "allowed_mentions": {"parse": []}}


def verify_signature(public_key_hex: str, body: bytes, timestamp: str | None, signature_hex: str | None) -> bool:
    """Verify Discord's Ed25519 signature over ``timestamp + body``."""
    if not public_key_hex or not timestamp or not signature_hex:
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), timestamp.encode() + body)
        return True
    except (ValueError, InvalidSignature):
        return False


def parse_interaction(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return (decision, action_value, user_id, user_name) for a button click."""
    if payload.get("type") != COMPONENT:
        raise ValueError("not a component interaction")
    custom_id = str((payload.get("data") or {}).get("custom_id", ""))
    decision, _, value = custom_id.partition("|")
    if decision not in (APPROVE, REJECT) or not value:
        raise ValueError("unknown component")
    user = (payload.get("member") or {}).get("user") or payload.get("user") or {}
    return decision, value, str(user.get("id", "")), str(user.get("username") or user.get("id", ""))


class DiscordChat:
    """Post and update approval cards in a Discord channel through the bot REST API."""
    name = "discord"

    def __init__(self, bot_token: str, channel_id: str, session: requests.Session | None = None,
                 timeout_s: float = 10) -> None:
        self.token = bot_token
        self.channel = channel_id
        self.session = session or requests.Session()
        self.timeout = timeout_s

    def _request(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Call the Discord API, retrying on 429 and 5xx responses."""
        for attempt in range(3):
            try:
                resp = self.session.request(method, f"{API}{path}", json=payload, timeout=self.timeout,
                                            headers={"Authorization": f"Bot {self.token}",
                                                     "User-Agent": "DiscordBot (hitl-soar-bot, 1.0)"})
            except requests.RequestException as exc:
                if attempt == 2:
                    raise ChatError(f"Discord {method} {path} network error: {type(exc).__name__}") from exc
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                try:
                    wait = float(resp.json().get("retry_after", 1))
                except ValueError:
                    wait = 1.0
                time.sleep(min(wait, 30))
                continue
            if resp.status_code >= 300:
                raise ChatError(f"Discord {method} {path} HTTP {resp.status_code}")
            return resp.json() if resp.content else {}
        raise ChatError("Discord rate limited")

    def send_approval_request(self, incident: Incident) -> tuple[str, str]:
        """Post the approval card. Returns ``(channel_id, message_id)``."""
        data = self._request("POST", f"/channels/{self.channel}/messages", build_message(incident))
        return self.channel, str(data["id"])

    def update(self, incident: Incident) -> None:
        """Edit the existing card to show the incident's current status."""
        if not incident.chat_channel or not incident.chat_message_ref:
            return
        self._request("PATCH", f"/channels/{incident.chat_channel}/messages/{incident.chat_message_ref}",
                      build_message(incident))
