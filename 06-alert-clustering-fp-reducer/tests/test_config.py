"""Tests for environment-based settings."""

import pytest

from alert_triage.config import ConfigError, Settings


def test_defaults_offline_without_key():
    s = Settings.from_env({})
    assert s.llm_provider == "offline" and s.algorithm == "dbscan" and s.dbscan_eps == 0.3
    assert s.llm_model == "claude-opus-5-5"


def test_key_enables_anthropic_and_overrides():
    s = Settings.from_env(
        {
            "ANTHROPIC_API_KEY": "x",
            "TRIAGE_ALGORITHM": "KMeans",
            "TRIAGE_DBSCAN_EPS": "0.2",
            "TRIAGE_TIME_WINDOW_S": "600",
            "TRIAGE_LLM_EFFORT": "high",
            "TRIAGE_DB_PATH": "/tmp/x.db",
        }
    )
    assert s.llm_provider == "anthropic" and s.algorithm == "kmeans" and s.dbscan_eps == 0.2
    assert s.time_window_s == 600 and isinstance(s.time_window_s, int) and s.llm_effort == "high"
    assert str(s.db_path) == "/tmp/x.db"


def test_explicit_offline_wins_over_key():
    assert Settings.from_env({"ANTHROPIC_API_KEY": "x", "TRIAGE_LLM_PROVIDER": "offline"}).llm_provider == "offline"


@pytest.mark.parametrize(
    "env",
    [
        {"TRIAGE_ALGORITHM": "hdbscan"},
        {"TRIAGE_LLM_PROVIDER": "gpt"},
        {"TRIAGE_LLM_EFFORT": "max"},
        {"TRIAGE_DBSCAN_EPS": "abc"},
        {"TRIAGE_DBSCAN_EPS": "1.5"},
        {"TRIAGE_TIME_WINDOW_S": "90.5"},
        {"TRIAGE_LLM_MIN_CONFIDENCE": "0.1"},
    ],
)
def test_invalid_values(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)
