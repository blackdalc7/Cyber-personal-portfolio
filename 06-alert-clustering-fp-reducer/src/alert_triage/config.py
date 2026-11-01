"""Configuration from environment variables / .env. The API key is read by the SDK and never logged."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when an environment variable holds an invalid value."""


def _num(env: Mapping[str, str], name: str, default: float, lo: float, hi: float, integer: bool = False) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    if integer and value != int(value):
        raise ConfigError(f"{name} must be an integer")
    return int(value) if integer else value


@dataclass(frozen=True)
class Settings:
    """Clustering, triage and LLM settings, loaded by :meth:`from_env`."""
    db_path: Path = Path("data/cmdb.sqlite")

    # Clustering
    algorithm: str = "dbscan"           # dbscan | kmeans
    dbscan_eps: float = 0.3             # cosine distance; 0.3 = documents at least 70% similar
    time_window_s: int = 3600           # a gap longer than this starts a new meta-alert
    kmeans_max_k: int = 60

    # LLM triage
    llm_provider: str = "offline"       # anthropic | offline
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "low"
    llm_timeout_s: float = 60.0
    llm_max_calls_per_minute: int = 30
    llm_workers: int = 4
    llm_failure_threshold: int = 3
    llm_cooldown_s: float = 300.0
    llm_min_confidence: float = 0.8     # LLM-only suppression needs at least this confidence

    # ROI model (stated assumptions, shown in the report)
    minutes_per_raw_alert: float = 4.0
    minutes_per_meta_alert: float = 12.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv_path: str | None = None) -> Settings:
        """Build settings from ``env`` (or ``os.environ`` plus an optional ``.env`` file).

        The LLM provider defaults to ``anthropic`` when ``ANTHROPIC_API_KEY`` is set and
        ``offline`` otherwise.

        Raises:
            ConfigError: if a value is invalid.
        """
        if env is None:
            load_dotenv(dotenv_path)
            env = os.environ
        algorithm = env.get("TRIAGE_ALGORITHM", "dbscan").strip().lower() or "dbscan"
        if algorithm not in {"dbscan", "kmeans"}:
            raise ConfigError("TRIAGE_ALGORITHM must be dbscan or kmeans")
        provider = env.get("TRIAGE_LLM_PROVIDER", "").strip().lower()
        if not provider:
            provider = "anthropic" if env.get("ANTHROPIC_API_KEY", "").strip() else "offline"
        if provider not in {"anthropic", "offline"}:
            raise ConfigError("TRIAGE_LLM_PROVIDER must be anthropic or offline")
        effort = env.get("TRIAGE_LLM_EFFORT", "low").strip().lower() or "low"
        if effort not in {"low", "medium", "high"}:
            raise ConfigError("TRIAGE_LLM_EFFORT must be low, medium or high")
        return cls(
            db_path=Path(env.get("TRIAGE_DB_PATH", "").strip() or cls.db_path),
            algorithm=algorithm,
            dbscan_eps=_num(env, "TRIAGE_DBSCAN_EPS", 0.3, 0.01, 0.99),
            time_window_s=_num(env, "TRIAGE_TIME_WINDOW_S", 3600, 60, 7 * 86400, integer=True),
            kmeans_max_k=_num(env, "TRIAGE_KMEANS_MAX_K", 60, 2, 1000, integer=True),
            llm_provider=provider,
            llm_model=env.get("TRIAGE_LLM_MODEL", "").strip() or cls.llm_model,
            llm_effort=effort,
            llm_timeout_s=_num(env, "TRIAGE_LLM_TIMEOUT_S", 60, 1, 600),
            llm_max_calls_per_minute=_num(env, "TRIAGE_LLM_MAX_CALLS_PER_MINUTE", 30, 1, 10_000, integer=True),
            llm_workers=_num(env, "TRIAGE_LLM_WORKERS", 4, 1, 64, integer=True),
            llm_failure_threshold=_num(env, "TRIAGE_LLM_FAILURE_THRESHOLD", 3, 1, 100, integer=True),
            llm_cooldown_s=_num(env, "TRIAGE_LLM_COOLDOWN_S", 300, 0, 86400),
            llm_min_confidence=_num(env, "TRIAGE_LLM_MIN_CONFIDENCE", 0.8, 0.5, 1.0),
            minutes_per_raw_alert=_num(env, "TRIAGE_MINUTES_PER_RAW_ALERT", 4.0, 0.1, 240),
            minutes_per_meta_alert=_num(env, "TRIAGE_MINUTES_PER_META_ALERT", 12.0, 0.1, 480),
        )
