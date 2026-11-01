"""Slack: Block Kit approval card, request-signature verification, and message updates."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import requests

from ..db import Incident
from .base import APPROVE, REJECT, ChatError, action_value, status_line, summary_fields

logger = logging.getLogger("soar_bot.slack")

API = "https://slack.com/api"
MAX_SKEW_S = 300


def build_blocks(incident: Incident) -> list[dict[str, Any]]:
    """Build the Slack Block Kit card for an incident.

    While the incident awaits approval the card has Approve (with a confirm
    dialog) and Reject buttons; afterwards the buttons are replaced by the status.
    """
    fields = [{"type": "mrkdwn", "text": f"*{k}*\n{_esc(v)}"} for k, v in summary_fields(incident)]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {incident.title}"[:150]}},
        {"type": "section", "fields": fields},
    ]
    if incident.description:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _esc(incident.description[:2800])}})
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": f"Incident `{incident.id}` · source `{_esc(incident.source)}`"}]})
    if incident.status == "awaiting_approval":
        value = action_value(incident)
        approve = [] if not incident.host else [
            {"type": "button", "action_id": "approve_isolation", "style": "danger", "value": value,
             "text": {"type": "plain_text", "text": "Approve Isolation"},
             "confirm": {"title": {"type": "plain_text", "text": "Isolate this host?"},
                         "text": {"type": "mrkdwn",
                                  "text": f"This will network-isolate *{_esc(incident.host or 'the host')}*. "
                                          "The decision is recorded under your name."},
                         "confirm": {"type": "plain_text", "text": "Isolate"},
                         "deny": {"type": "plain_text", "text": "Cancel"}}}]
        blocks.append({"type": "actions", "block_id": "hitl_decision", "elements": [
            *approve,
            {"type": "button", "action_id": "reject_isolation", "value": value,
             "text": {"type": "plain_text", "text": "Reject"}},
        ]})
    blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Status:* {status_line(incident)}"}})
    return blocks


def _esc(text: str) -> str:
    """Escape Slack mrkdwn control characters so alert content cannot forge links or mentions."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def verify_signature(signing_secret: str, body: bytes, timestamp: str | None, signature: str | None,
                     now: float | None = None) -> bool:
    """Slack v0 signing: HMAC-SHA256 of ``v0:{ts}:{body}``; reject stale timestamps (replay)."""
    if not signing_secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs((now or time.time()) - ts) > MAX_SKEW_S:
        return False
    base = f"v0:{ts}:".encode() + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def sign_request(signing_secret: str, body: bytes, timestamp: int | None = None) -> dict[str, str]:
    """Produce Slack-style signature headers (used by the local click simulator and tests)."""
    ts = str(timestamp if timestamp is not None else int(time.time()))
    sig = "v0=" + hmac.new(signing_secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}


def parse_interaction(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return (decision, action_value, user_id, user_name) from a block_actions payload."""
    if payload.get("type") != "block_actions":
        raise ValueError("unsupported interaction type")
    actions = payload.get("actions") or []
    if not actions:
        raise ValueError("no action in payload")
    action = actions[0]
    decision = {"approve_isolation": APPROVE, "reject_isolation": REJECT}.get(action.get("action_id"))
    if decision is None:
        raise ValueError("unknown action")
    user = payload.get("user") or {}
    return decision, str(action.get("value", "")), str(user.get("id", "")), str(user.get("username") or
                                                                                  user.get("name") or user.get("id"))


class SlackChat:
    """Post and update approval cards in a Slack channel through the Web API."""
    name = "slack"

    def __init__(self, bot_token: str, channel: str, session: requests.Session | None = None,
                 timeout_s: float = 10) -> None:
        self.token = bot_token
        self.channel = channel
        self.session = session or requests.Session()
        self.timeout = timeout_s

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Call a Slack Web API method, retrying on rate limits and transient errors."""
        for attempt in range(3):
            try:
                resp = self.session.post(f"{API}/{method}", data=json.dumps(payload), timeout=self.timeout,
                                         headers={"Authorization": f"Bearer {self.token}",
                                                  "Content-Type": "application/json; charset=utf-8"})
            except requests.RequestException as exc:
                if attempt == 2:
                    raise ChatError(f"Slack {method} network error: {type(exc).__name__}") from exc
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                time.sleep(min(int(resp.headers.get("Retry-After", "1")), 30))
                continue
            try:
                data = resp.json()
            except ValueError as exc:
                raise ChatError(f"Slack {method} returned non-JSON (HTTP {resp.status_code})") from exc
            if not data.get("ok"):
                raise ChatError(f"Slack {method} failed: {data.get('error', 'unknown_error')}")
            return data
        raise ChatError(f"Slack {method} rate limited")

    def send_approval_request(self, incident: Incident) -> tuple[str, str]:
        """Post the approval card. Returns ``(channel_id, message_ts)``."""
        data = self._call("chat.postMessage", {
            "channel": self.channel, "text": f"Approval needed: {incident.title}",
            "blocks": build_blocks(incident), "unfurl_links": False})
        return data["channel"], data["ts"]

    def update(self, incident: Incident) -> None:
        """Replace the existing card with the incident's current status."""
        if not incident.chat_channel or not incident.chat_message_ref:
            return
        self._call("chat.update", {"channel": incident.chat_channel, "ts": incident.chat_message_ref,
                                   "text": f"{incident.title}: {status_line(incident)}",
                                   "blocks": build_blocks(incident)})
