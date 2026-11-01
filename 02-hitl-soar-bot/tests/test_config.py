"""Tests for settings validation and secret handling."""

import pytest

from soar_bot.config import ConfigError, Settings
from soar_bot.server import build_chat, build_service

SECRET = "s" * 40


def test_requires_webhook_secret():
    with pytest.raises(ConfigError, match="WEBHOOK_SHARED_SECRET"):
        Settings.from_env({})
    with pytest.raises(ConfigError):
        Settings.from_env({"WEBHOOK_SHARED_SECRET": "short"})


def test_outbox_default(tmp_path):
    s = Settings.from_env({"WEBHOOK_SHARED_SECRET": SECRET, "SOAR_DATA_DIR": str(tmp_path)})
    assert s.chat_mode == "outbox" and s.database_path == tmp_path / "soar.db"
    assert build_chat(s)[0].name == "outbox"
    service = build_service(s)
    assert service.db.path.exists()
    service.shutdown()


def test_slack_mode_requires_signing_secret_and_approvers():
    base = {"WEBHOOK_SHARED_SECRET": SECRET, "SLACK_BOT_TOKEN": "xoxb", "SLACK_CHANNEL_ID": "C1"}
    with pytest.raises(ConfigError, match="SIGNING"):
        Settings.from_env(base)
    with pytest.raises(ConfigError, match="APPROVER"):
        Settings.from_env({**base, "SLACK_SIGNING_SECRET": "x"})
    s = Settings.from_env({**base, "SLACK_SIGNING_SECRET": "x", "SLACK_APPROVER_IDS": "U1, U2"})
    assert s.chat_mode == "slack" and s.slack_approver_ids == {"U1", "U2"}
    chat, approvers = build_chat(s)
    assert chat.name == "slack" and approvers == {"U1", "U2"}


def test_discord_mode_requirements():
    base = {"WEBHOOK_SHARED_SECRET": SECRET, "DISCORD_BOT_TOKEN": "t", "DISCORD_CHANNEL_ID": "1"}
    with pytest.raises(ConfigError, match="PUBLIC_KEY"):
        Settings.from_env(base)
    with pytest.raises(ConfigError, match="APPROVER"):
        Settings.from_env({**base, "DISCORD_PUBLIC_KEY": "ab"})
    s = Settings.from_env({**base, "DISCORD_PUBLIC_KEY": "ab", "DISCORD_APPROVER_IDS": "9"})
    assert build_chat(s)[0].name == "discord"


@pytest.mark.parametrize("env", [{"LISTEN_PORT": "x"}, {"HITL_MIN_SEVERITY": "urgent"}, {"DRY_RUN": "maybe"},
                                 {"HITL_APPROVAL_TTL_S": "5"}])
def test_invalid_values(env):
    with pytest.raises(ConfigError):
        Settings.from_env({"WEBHOOK_SHARED_SECRET": SECRET, **env})


def test_secrets_not_in_repr():
    s = Settings.from_env({"WEBHOOK_SHARED_SECRET": SECRET, "SLACK_BOT_TOKEN": "xoxb-zzz",
                           "SLACK_SIGNING_SECRET": "q", "SLACK_CHANNEL_ID": "C", "SLACK_APPROVER_IDS": "U"})
    assert SECRET not in repr(s) and "xoxb-zzz" not in repr(s)
