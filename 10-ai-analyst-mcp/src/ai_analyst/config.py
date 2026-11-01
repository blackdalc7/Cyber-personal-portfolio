"""Settings from ``ANALYST_*`` environment variables (and an optional ``.env``)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

PROVIDERS = ("offline", "anthropic", "ollama")


class ConfigError(ValueError):
    """An environment variable holds an invalid value."""


def _int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    lake_dir: Path = Path("lake")
    cmdb_path: Path = Path("examples/cmdb.sqlite")
    cmdb_seed: Path | None = None  # used to build a throwaway CMDB when cmdb_path does not exist
    out_dir: Path = Path("analyst")
    provider: str = "offline"
    model: str = "claude-opus-5-5"
    effort: str = "high"
    anthropic_api_key: str = field(default="", repr=False)
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:32b"
    max_tool_calls: int = 16
    max_rows: int = 100
    timeout_s: int = 300

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv: bool = True) -> Settings:
        if env is None:
            if dotenv:
                load_dotenv(override=False)
            env = os.environ
        cmdb_path = Path(env.get("ANALYST_CMDB_PATH", "").strip() or cls.cmdb_path)
        seed = env.get("ANALYST_CMDB_SEED", "").strip()
        s = cls(
            lake_dir=Path(env.get("ANALYST_LAKE_DIR", "").strip() or cls.lake_dir),
            cmdb_path=cmdb_path,
            cmdb_seed=Path(seed) if seed else cmdb_path.with_name("cmdb_seed.yml"),
            out_dir=Path(env.get("ANALYST_OUT_DIR", "").strip() or cls.out_dir),
            provider=env.get("ANALYST_PROVIDER", "").strip().lower() or cls.provider,
            model=env.get("ANALYST_MODEL", "").strip() or cls.model,
            effort=env.get("ANALYST_EFFORT", "").strip().lower() or cls.effort,
            anthropic_api_key=env.get("ANTHROPIC_API_KEY", "").strip(),
            ollama_url=(env.get("OLLAMA_URL", "").strip() or cls.ollama_url).rstrip("/"),
            ollama_model=env.get("OLLAMA_MODEL", "").strip() or cls.ollama_model,
            max_tool_calls=_int(env, "ANALYST_MAX_TOOL_CALLS", cls.max_tool_calls, 1, 64),
            max_rows=_int(env, "ANALYST_MAX_ROWS", cls.max_rows, 1, 500),
            timeout_s=_int(env, "ANALYST_TIMEOUT_S", cls.timeout_s, 10, 3600),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.provider not in PROVIDERS:
            raise ConfigError(f"ANALYST_PROVIDER must be one of {', '.join(PROVIDERS)}")
        if self.effort not in ("low", "medium", "high", "xhigh", "max"):
            raise ConfigError("ANALYST_EFFORT must be low, medium, high, xhigh or max")
        if self.provider == "ollama" and urlparse(self.ollama_url).scheme not in ("http", "https"):
            raise ConfigError("OLLAMA_URL must be an http(s) URL")
