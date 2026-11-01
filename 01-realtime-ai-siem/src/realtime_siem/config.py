"""Runtime configuration, loaded once from the environment (and an optional .env file).

Nothing in this module holds a secret. The Anthropic SDK reads ``ANTHROPIC_API_KEY``
itself; we only check whether it is present to decide between live and offline
summarisation.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ConfigError(ValueError):
    """Raised when an environment variable holds an invalid value."""


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
    """Read an integer variable, falling back to ``default`` when unset and enforcing ``minimum``."""
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    """Read a boolean variable (1/0, true/false, yes/no, on/off), falling back to ``default`` when unset."""
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _networks(env: Mapping[str, str], name: str) -> tuple[IPNetwork, ...]:
    """Parse a comma-separated list of CIDRs into IP network objects (empty tuple when unset)."""
    raw = env.get(name, "").strip()
    if not raw:
        return ()
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError as exc:
            raise ConfigError(f"{name} contains an invalid CIDR: {part!r}") from exc
    return tuple(nets)


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings for the listener, detections, chain correlation and LLM.

    Every field has a safe default, so the SIEM runs with no configuration at all.
    Use :meth:`from_env` to build an instance from environment variables.
    """
    # --- Listener -----------------------------------------------------------
    # A collector must listen on the network; restrict senders with SYSLOG_ALLOWED_SOURCES + firewall.
    bind_host: str = "0.0.0.0"  # noqa: S104
    bind_port: int = 5514
    allowed_sources: tuple[IPNetwork, ...] = ()
    queue_max: int = 10_000
    default_timezone: str = "UTC"

    # --- Storage (RotatingFileHandler) ---------------------------------------
    output_dir: Path = Path("data")
    rotate_max_bytes: int = 50 * 1024 * 1024
    rotate_backup_count: int = 10

    # --- Detection ------------------------------------------------------------
    brute_force_threshold: int = 10
    brute_force_window_s: int = 900
    spray_user_threshold: int = 5
    spray_window_s: int = 900
    post_compromise_window_s: int = 3600
    alert_cooldown_s: int = 300
    max_tracked_keys: int = 100_000

    # --- Alert chains -------------------------------------------------------
    chain_window_s: int = 3600
    chain_min_alerts: int = 2
    chain_resummarize_s: int = 120

    # --- LLM ----------------------------------------------------------------
    llm_provider: str = "offline"
    llm_model: str = "claude-opus-5-5"
    llm_effort: str = "medium"
    llm_timeout_s: int = 60
    llm_max_calls_per_minute: int = 6
    llm_redact: bool = False
    llm_failure_threshold: int = 3
    llm_circuit_cooldown_s: int = 300

    stats_interval_s: int = 60

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv_path: str | None = None) -> Settings:
        """Build settings from ``env`` (or ``os.environ`` plus an optional ``.env`` file).

        The LLM provider defaults to ``anthropic`` when ``ANTHROPIC_API_KEY`` is set and
        ``offline`` otherwise.

        Raises:
            ConfigError: if any variable holds an invalid value.
        """
        if env is None:
            load_dotenv(dotenv_path)
            env = os.environ

        provider = env.get("LLM_PROVIDER", "").strip().lower()
        if not provider:
            provider = "anthropic" if env.get("ANTHROPIC_API_KEY") else "offline"
        if provider not in {"anthropic", "offline"}:
            raise ConfigError(f"LLM_PROVIDER must be 'anthropic' or 'offline', got {provider!r}")

        effort = env.get("LLM_EFFORT", "medium").strip().lower() or "medium"
        if effort not in {"low", "medium", "high", "xhigh", "max"}:
            raise ConfigError(f"LLM_EFFORT must be low|medium|high|xhigh|max, got {effort!r}")

        return cls(
            bind_host=env.get("SYSLOG_BIND_HOST", "").strip() or cls.bind_host,
            bind_port=_int(env, "SYSLOG_BIND_PORT", 5514, minimum=0),
            allowed_sources=_networks(env, "SYSLOG_ALLOWED_SOURCES"),
            queue_max=_int(env, "SYSLOG_QUEUE_MAX", 10_000, minimum=1),
            default_timezone=env.get("SYSLOG_DEFAULT_TZ", "UTC").strip() or "UTC",
            output_dir=Path(env.get("SIEM_OUTPUT_DIR", "data").strip() or "data"),
            rotate_max_bytes=_int(env, "SIEM_ROTATE_MAX_BYTES", 50 * 1024 * 1024, minimum=1024),
            rotate_backup_count=_int(env, "SIEM_ROTATE_BACKUP_COUNT", 10, minimum=1),
            brute_force_threshold=_int(env, "DETECT_BRUTE_FORCE_THRESHOLD", 10, minimum=1),
            brute_force_window_s=_int(env, "DETECT_BRUTE_FORCE_WINDOW_S", 900, minimum=1),
            spray_user_threshold=_int(env, "DETECT_SPRAY_USER_THRESHOLD", 5, minimum=2),
            spray_window_s=_int(env, "DETECT_SPRAY_WINDOW_S", 900, minimum=1),
            post_compromise_window_s=_int(env, "DETECT_POST_COMPROMISE_WINDOW_S", 3600, minimum=1),
            alert_cooldown_s=_int(env, "DETECT_ALERT_COOLDOWN_S", 300, minimum=0),
            max_tracked_keys=_int(env, "DETECT_MAX_TRACKED_KEYS", 100_000, minimum=100),
            chain_window_s=_int(env, "CHAIN_WINDOW_S", 3600, minimum=1),
            chain_min_alerts=_int(env, "CHAIN_MIN_ALERTS", 2, minimum=1),
            chain_resummarize_s=_int(env, "CHAIN_RESUMMARIZE_S", 120, minimum=0),
            llm_provider=provider,
            llm_model=env.get("LLM_MODEL", "").strip() or "claude-opus-5-5",
            llm_effort=effort,
            llm_timeout_s=_int(env, "LLM_TIMEOUT_S", 60, minimum=1),
            llm_max_calls_per_minute=_int(env, "LLM_MAX_CALLS_PER_MINUTE", 6, minimum=1),
            llm_redact=_bool(env, "LLM_REDACT", False),
            llm_failure_threshold=_int(env, "LLM_FAILURE_THRESHOLD", 3, minimum=1),
            llm_circuit_cooldown_s=_int(env, "LLM_CIRCUIT_COOLDOWN_S", 300, minimum=1),
            stats_interval_s=_int(env, "SIEM_STATS_INTERVAL_S", 60, minimum=0),
        )

    def source_allowed(self, ip: str) -> bool:
        """True when no allow-list is configured or ``ip`` falls inside one of its CIDRs."""
        if not self.allowed_sources:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allowed_sources)
