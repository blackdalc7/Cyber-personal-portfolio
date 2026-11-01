"""Shared test helpers."""

from __future__ import annotations

import json
import time
from concurrent.futures import Future
from pathlib import Path
from urllib.parse import urlencode

from soar_bot.chat.slack import sign_request
from soar_bot.ingest import sign_body

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "alerts" / "samples"
WEBHOOK_SECRET = "w" * 40
SLACK_SECRET = "slack-signing-secret-for-tests"
APPROVER = "U0APPROVER"


class SyncExecutor:
    """Runs submitted work inline so tests are deterministic."""

    def submit(self, fn, *args, **kwargs):
        fut: Future = Future()
        try:
            fut.set_result(fn(*args, **kwargs))
        except Exception as exc:  # pragma: no cover - surfaced via fut
            fut.set_exception(exc)
        return fut

    def shutdown(self, wait: bool = True) -> None:
        pass


class FakeClock:
    def __init__(self, start: float = 1_793_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingChat:
    name = "recording"

    def __init__(self, fail: bool = False) -> None:
        self.sent = []
        self.updates = []
        self.fail = fail

    def send_approval_request(self, incident):
        if self.fail:
            from soar_bot.chat import ChatError
            raise ChatError("slack down")
        self.sent.append(incident)
        return "C123", f"ts-{len(self.sent)}"

    def update(self, incident):
        self.updates.append(incident.status)


def signed_alert(client, payload, secret=WEBHOOK_SECRET, ts=None, content_type="application/json"):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    t, sig = sign_body(secret, body, ts)
    return client.post("/alerts", data=body, content_type=content_type,
                       headers={"X-SOAR-Timestamp": t, "X-SOAR-Signature": sig})


def slack_click(client, value, action="approve_isolation", user=APPROVER, secret=SLACK_SECRET, ts=None,
                response_url=None):
    payload = {"type": "block_actions", "user": {"id": user, "username": "analyst"},
               "actions": [{"action_id": action, "value": value}]}
    if response_url:
        payload["response_url"] = response_url
    body = urlencode({"payload": json.dumps(payload)}).encode()
    headers = sign_request(secret, body, ts if ts is not None else int(time.time()))
    return client.post("/slack/interactions", data=body, headers=headers,
                       content_type="application/x-www-form-urlencoded")
