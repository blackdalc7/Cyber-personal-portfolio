"""Runtime configuration from environment variables (and an optional ``.env`` file)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when an environment variable holds an invalid value."""


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
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


def _path(env: Mapping[str, str], name: str) -> Path | None:
    raw = env.get(name, "").strip()
    return Path(raw) if raw else None


@dataclass(frozen=True)
class Settings:
    """All Watchfloor settings. Build with :meth:`from_env`."""
    redis_url: str = "redis://localhost:6379/0"
    stream: str = "wf:events"
    dead_letter_stream: str = "wf:dead"
    stream_maxlen: int = 200_000
    lake_dir: Path = Path("lake")
    flush_rows: int = 2_000
    flush_interval_s: int = 5
    hub_token: str = ""
    ingest_token: str = ""
    max_ingest_bytes: int = 5_000_000
    cors_origins: tuple[str, ...] = ()
    coverage_dir: Path | None = None
    exposure_file: Path | None = None
    rules_index: Path | None = None
    evidence_dir: Path | None = None
    analyst_dir: Path | None = None
    scenarios_dir: Path = Path("../datasets/scenarios")
    ui_dir: Path | None = None
    soar_url: str = ""
    soar_token: str = ""
    adapter_state: Path = Path("lake/_adapter_state.json")
    siem_dir: Path | None = None
    edr_alerts: Path | None = None
    triage_queue: Path | None = None
    poll_interval_s: int = 5
    actions_enabled: bool = False
    soar_webhook_secret: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv: bool = True) -> Settings:
        """Read ``WF_*`` variables; unset ones keep their defaults."""
        if env is None:
            if dotenv:
                load_dotenv(override=False)
            env = os.environ
        lake = Path(env.get("WF_LAKE_DIR", "lake"))
        origins = tuple(o.strip() for o in env.get("WF_CORS_ORIGINS", "").split(",") if o.strip())
        return cls(
            redis_url=env.get("WF_REDIS_URL", cls.redis_url),
            stream=env.get("WF_STREAM", cls.stream),
            dead_letter_stream=env.get("WF_DEAD_LETTER_STREAM", cls.dead_letter_stream),
            stream_maxlen=_int(env, "WF_STREAM_MAXLEN", cls.stream_maxlen, 1000),
            lake_dir=lake,
            flush_rows=_int(env, "WF_FLUSH_ROWS", cls.flush_rows, 1),
            flush_interval_s=_int(env, "WF_FLUSH_INTERVAL_S", cls.flush_interval_s, 1),
            hub_token=env.get("WF_HUB_TOKEN", ""),
            ingest_token=env.get("WF_INGEST_TOKEN", ""),
            max_ingest_bytes=_int(env, "WF_MAX_INGEST_BYTES", cls.max_ingest_bytes, 1024),
            cors_origins=origins,
            coverage_dir=_path(env, "WF_COVERAGE_DIR"),
            exposure_file=_path(env, "WF_EXPOSURE_FILE"),
            rules_index=_path(env, "WF_RULES_INDEX"),
            evidence_dir=_path(env, "WF_EVIDENCE_DIR"),
            analyst_dir=_path(env, "WF_ANALYST_DIR"),
            scenarios_dir=Path(env.get("WF_SCENARIOS_DIR", "../datasets/scenarios")),
            ui_dir=_path(env, "WF_UI_DIR"),
            soar_url=env.get("WF_SOAR_URL", "").rstrip("/"),
            soar_token=env.get("WF_SOAR_TOKEN", ""),
            adapter_state=Path(env.get("WF_ADAPTER_STATE", str(lake / "_adapter_state.json"))),
            siem_dir=_path(env, "WF_SIEM_DIR"),
            edr_alerts=_path(env, "WF_EDR_ALERTS"),
            triage_queue=_path(env, "WF_TRIAGE_QUEUE"),
            poll_interval_s=_int(env, "WF_POLL_INTERVAL_S", cls.poll_interval_s, 1),
            actions_enabled=env.get("WF_ACTIONS_ENABLED", "").strip().lower() in ("1", "true", "yes"),
            soar_webhook_secret=env.get("WF_SOAR_WEBHOOK_SECRET", ""),
        )
