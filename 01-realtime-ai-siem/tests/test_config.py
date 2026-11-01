"""Tests for environment-based settings: defaults, provider selection and validation."""

import pytest

from realtime_siem.config import ConfigError, Settings


def test_defaults_are_offline_without_key():
    s = Settings.from_env({})
    assert s.llm_provider == "offline" and s.bind_port == 5514 and s.llm_model == "claude-opus-5-5"


def test_key_presence_selects_anthropic():
    assert Settings.from_env({"ANTHROPIC_API_KEY": "sk-test"}).llm_provider == "anthropic"


def test_parsing_and_allow_list():
    s = Settings.from_env({"SYSLOG_BIND_PORT": "6514", "SYSLOG_ALLOWED_SOURCES": "10.0.0.0/8, 192.168.1.5",
                           "LLM_REDACT": "yes", "LLM_EFFORT": "LOW"})
    assert s.bind_port == 6514 and s.llm_redact and s.llm_effort == "low"
    assert s.source_allowed("10.2.3.4") and s.source_allowed("192.168.1.5")
    assert not s.source_allowed("8.8.8.8") and not s.source_allowed("not-an-ip")
    assert Settings.from_env({}).source_allowed("8.8.8.8")


@pytest.mark.parametrize("env", [
    {"SYSLOG_BIND_PORT": "abc"},
    {"SIEM_ROTATE_MAX_BYTES": "10"},
    {"LLM_PROVIDER": "openai"},
    {"LLM_EFFORT": "extreme"},
    {"LLM_REDACT": "perhaps"},
    {"SYSLOG_ALLOWED_SOURCES": "10.0.0.0/33"},
])
def test_invalid_values_rejected(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)
