from __future__ import annotations

from pathlib import Path

import pytest

from ai_analyst.config import ConfigError, Settings


def test_defaults_and_env() -> None:
    s = Settings.from_env({}, dotenv=False)
    assert (s.provider, s.model, s.effort, s.max_tool_calls) == ("offline", "claude-opus-5-5", "high", 16)
    assert s.cmdb_seed == Path("examples/cmdb_seed.yml")
    s = Settings.from_env({"ANALYST_PROVIDER": "Anthropic", "ANALYST_CMDB_PATH": "/cmdb/cmdb.sqlite",
                           "ANALYST_MAX_ROWS": "20", "OLLAMA_URL": "http://x:1/"}, dotenv=False)
    assert s.provider == "anthropic" and s.cmdb_seed == Path("/cmdb/cmdb_seed.yml") and s.max_rows == 20
    assert s.ollama_url == "http://x:1"
    assert "sk-" not in repr(Settings.from_env({"ANTHROPIC_API_KEY": "sk-secret"}, dotenv=False))


@pytest.mark.parametrize("env", [{"ANALYST_PROVIDER": "openai"}, {"ANALYST_EFFORT": "huge"},
                                 {"ANALYST_MAX_TOOL_CALLS": "0"}, {"ANALYST_MAX_ROWS": "x"},
                                 {"ANALYST_PROVIDER": "ollama", "OLLAMA_URL": "file:///etc"}])
def test_invalid(env) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env, dotenv=False)
