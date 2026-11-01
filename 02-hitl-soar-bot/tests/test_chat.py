"""Tests for the Slack, Discord and outbox approval cards and their signature checks."""

import json
import time
from dataclasses import replace

import pytest
import responses
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from helpers import APPROVER, slack_click

from soar_bot.app import create_app
from soar_bot.chat import ChatError, DiscordChat, OutboxChat, SlackChat
from soar_bot.chat import discord as dc
from soar_bot.chat.base import action_value, parse_action_value, status_line
from soar_bot.chat.slack import build_blocks, parse_interaction, verify_signature
from soar_bot.ingest import normalise


@pytest.fixture
def incident(service):
    inc, _ = service.handle_alert(normalise({"id": "x1", "title": "Brute force <@here>", "severity": "critical",
                                             "host": "web01", "source_ip": "203.0.113.66",
                                             "description": "<https://evil|click> me"}))
    return inc


def test_slack_blocks_have_approve_button_with_confirm(incident):
    blocks = build_blocks(incident)
    actions = next(b for b in blocks if b["type"] == "actions")
    approve = actions["elements"][0]
    assert approve["action_id"] == "approve_isolation" and approve["text"]["text"] == "Approve Isolation"
    assert approve["style"] == "danger" and "confirm" in approve
    assert approve["value"] == action_value(incident)
    text = json.dumps(blocks)
    assert "<https://evil" not in text and "&lt;https://evil" in text  # mrkdwn injection escaped


def test_slack_blocks_drop_buttons_after_decision(incident):
    assert not [b for b in build_blocks(replace(incident, status="remediated")) if b["type"] == "actions"]


def test_parse_helpers():
    assert parse_action_value("INC-1:abc") == ("INC-1", "abc")
    with pytest.raises(ValueError):
        parse_action_value("nonce-only")
    with pytest.raises(ValueError):
        parse_interaction({"type": "view_submission"})
    with pytest.raises(ValueError):
        parse_interaction({"type": "block_actions", "actions": [{"action_id": "other"}]})
    assert not verify_signature("s", b"b", "notanint", "v0=x")


@pytest.mark.parametrize("status", ["awaiting_approval", "approved", "remediating", "remediated", "failed",
                                    "rejected", "expired", "closed"])
def test_status_lines(incident, status):
    assert status_line(replace(incident, status=status))


@responses.activate
def test_slack_chat_post_and_update(incident):
    responses.post("https://slack.com/api/chat.postMessage", json={"ok": True, "channel": "C9", "ts": "1.2"})
    responses.post("https://slack.com/api/chat.update", json={"ok": True})
    chat = SlackChat("xoxb-test", "C9")
    assert chat.send_approval_request(incident) == ("C9", "1.2")
    chat.update(replace(incident, chat_channel="C9", chat_message_ref="1.2", status="approved"))
    sent = json.loads(responses.calls[0].request.body)
    assert sent["channel"] == "C9" and sent["blocks"]
    assert responses.calls[0].request.headers["Authorization"] == "Bearer xoxb-test"
    assert json.loads(responses.calls[1].request.body)["ts"] == "1.2"


@responses.activate
def test_slack_chat_errors(incident, monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    responses.post("https://slack.com/api/chat.postMessage", json={"ok": False, "error": "channel_not_found"})
    with pytest.raises(ChatError, match="channel_not_found"):
        SlackChat("t", "C1").send_approval_request(incident)
    responses.replace(responses.POST, "https://slack.com/api/chat.postMessage", status=429,
                      headers={"Retry-After": "1"})
    with pytest.raises(ChatError, match="rate limited"):
        SlackChat("t", "C1").send_approval_request(incident)


def test_slack_ephemeral_reply_is_ssrf_guarded(client, service, incident):
    calls = []

    class Spy:
        def post(self, url, **kw):
            calls.append(url)

    app = create_app(service_settings(client), service, http=Spy())
    tc = app.test_client()
    slack_click(tc, action_value(incident), user="U0NOBODY", response_url="http://169.254.169.254/latest")
    slack_click(tc, action_value(incident), user="U0NOBODY", response_url="https://hooks.slack.com/actions/T/1")
    assert calls == ["https://hooks.slack.com/actions/T/1"]


def service_settings(client):
    # The client fixture's app already holds settings; rebuild an equivalent one.
    from helpers import SLACK_SECRET, WEBHOOK_SECRET

    from soar_bot.config import Settings
    return replace(Settings(), webhook_secret=WEBHOOK_SECRET, slack_signing_secret=SLACK_SECRET,
                   slack_approver_ids=frozenset({APPROVER}))


def test_outbox_writes_cards(tmp_path, incident):
    box = OutboxChat(tmp_path)
    channel, ref = box.send_approval_request(incident)
    box.update(replace(incident, status="remediated"))
    files = sorted(p.name for p in tmp_path.iterdir())
    assert channel == "outbox" and files[0] == ref and files[1].endswith("-update.json")


# -- Discord -----------------------------------------------------------------

@pytest.fixture
def ed25519():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return key, pub


def discord_post(client, key, payload, tamper=False):
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = key.sign(ts.encode() + body).hex()
    if tamper:
        body = body.replace(b"approve", b"reject")
    return client.post("/discord/interactions", data=body, content_type="application/json",
                       headers={"X-Signature-Ed25519": sig, "X-Signature-Timestamp": ts})


def test_discord_ping_click_and_tamper(settings, service, ed25519, incident):
    key, pub = ed25519
    app = create_app(replace(settings, discord_public_key=pub), service)
    service.approvers = frozenset({"111"})
    tc = app.test_client()
    assert discord_post(tc, key, {"type": 1}).get_json() == {"type": 1}
    click = {"type": 3, "data": {"custom_id": f"approve|{action_value(incident)}"},
             "member": {"user": {"id": "111", "username": "dana"}}}
    assert discord_post(tc, key, click, tamper=True).status_code == 401
    other = {**click, "member": {"user": {"id": "999", "username": "eve"}}}
    denied = discord_post(tc, key, other).get_json()
    assert denied["type"] == 4 and denied["data"]["flags"] == 64
    ok = discord_post(tc, key, click).get_json()
    assert ok["type"] == 7 and ok["data"]["components"] == []
    assert service.db.get(incident.id).status == "remediated"


def test_discord_message_shape(incident):
    msg = dc.build_message(incident)
    buttons = msg["components"][0]["components"]
    assert [b["label"] for b in buttons] == ["Approve Isolation", "Reject"]
    assert msg["allowed_mentions"] == {"parse": []}
    assert dc.build_message(replace(incident, host=None))["components"][0]["components"][0]["label"] == "Reject"


@responses.activate
def test_discord_chat_api(incident):
    responses.post("https://discord.com/api/v10/channels/42/messages", json={"id": "777"})
    responses.patch("https://discord.com/api/v10/channels/42/messages/777", json={"id": "777"})
    chat = DiscordChat("bot-token", "42")
    assert chat.send_approval_request(incident) == ("42", "777")
    chat.update(replace(incident, chat_channel="42", chat_message_ref="777", status="rejected"))
    assert responses.calls[0].request.headers["Authorization"] == "Bot bot-token"
    responses.post("https://discord.com/api/v10/channels/43/messages", status=403)
    with pytest.raises(ChatError):
        DiscordChat("t", "43").send_approval_request(incident)


def test_discord_signature_rejects_garbage():
    assert not dc.verify_signature("zz", b"x", "1", "00")
    assert not dc.verify_signature("", b"x", "1", "00")
