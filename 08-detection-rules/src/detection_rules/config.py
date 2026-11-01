"""Settings from ``RULES_*`` environment variables (and an optional ``.env``)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """An environment variable holds an invalid value."""


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


HERE = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    """Runtime settings, read from ``RULES_*`` environment variables (and ``.env``) by ``from_env``."""
    rules_dir: Path = HERE / "rules"
    samples_dir: Path = HERE / "samples"
    build_dir: Path = HERE / "build"
    lake_dir: Path = Path("lake")
    hub_url: str = ""
    ingest_token: str = ""
    state_file: Path = Path("state/state.json")
    lookback_s: int = 3600
    overlap_s: int = 120
    max_findings_per_rule: int = 200

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv: bool = True) -> Settings:
        """Build settings from ``env`` (default ``os.environ``), raising ``ConfigError`` on invalid values."""
        if env is None:
            if dotenv:
                load_dotenv(override=False)
            env = os.environ

        def path(name: str, default: Path) -> Path:
            raw = env.get(name, "").strip()
            return Path(raw) if raw else default

        return cls(
            rules_dir=path("RULES_RULES_DIR", cls.rules_dir),
            samples_dir=path("RULES_SAMPLES_DIR", cls.samples_dir),
            build_dir=path("RULES_BUILD_DIR", cls.build_dir),
            lake_dir=path("RULES_LAKE_DIR", cls.lake_dir),
            hub_url=env.get("RULES_HUB_URL", "").rstrip("/"),
            ingest_token=env.get("RULES_INGEST_TOKEN", ""),
            state_file=path("RULES_STATE_FILE", cls.state_file),
            lookback_s=_int(env, "RULES_LOOKBACK_S", cls.lookback_s, 0),
            overlap_s=_int(env, "RULES_OVERLAP_S", cls.overlap_s, 0),
            max_findings_per_rule=_int(env, "RULES_MAX_FINDINGS_PER_RULE", cls.max_findings_per_rule, 1),
        )
