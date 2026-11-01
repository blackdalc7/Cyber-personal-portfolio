"""Configuration from environment variables / .env. Secrets are read here and never logged."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when the environment holds an invalid or unsafe configuration."""


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 0) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean")


def _csv(env: Mapping[str, str], name: str) -> frozenset[str]:
    return frozenset(p.strip() for p in env.get(name, "").split(",") if p.strip())


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings, loaded from the environment by :meth:`from_env`.

    Secrets are excluded from ``repr`` so they never end up in logs.
    """
    # HTTP listener
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    public_base_url: str = ""
    max_body_bytes: int = 256 * 1024

    # Storage
    database_path: Path = Path("data/soar.db")
    data_dir: Path = Path("data")

    # Inbound alert authentication (HMAC-SHA256 over the raw body)
    webhook_secret: str = field(default="", repr=False)
    # Bearer token for the read API (/incidents, /metrics). Empty disables those endpoints.
    api_token: str = field(default="", repr=False)

    # Slack
    slack_bot_token: str = field(default="", repr=False)
    slack_signing_secret: str = field(default="", repr=False)
    slack_channel: str = ""
    slack_approver_ids: frozenset[str] = frozenset()

    # Discord
    discord_bot_token: str = field(default="", repr=False)
    discord_public_key: str = ""
    discord_channel_id: str = ""
    discord_approver_ids: frozenset[str] = frozenset()

    # Human-in-the-loop policy
    approval_ttl_s: int = 3600
    expiry_sweep_s: int = 30
    min_severity_for_approval: str = "medium"

    # Remediation
    remediation_script: Path = Path(__file__).resolve().parents[2] / "scripts" / "mock_isolate.py"
    remediation_timeout_s: int = 60
    dry_run: bool = False

    # Outbound decision webhook (n8n). Empty URL disables it.
    decision_webhook_url: str = ""
    decision_webhook_secret: str = field(default="", repr=False)

    # Enrichment
    abuseipdb_api_key: str = field(default="", repr=False)
    intel_timeout_s: int = 10

    @property
    def chat_mode(self) -> str:
        """Which chat backend is configured: ``slack``, ``discord`` or ``outbox``."""
        if self.slack_bot_token and self.slack_channel:
            return "slack"
        if self.discord_bot_token and self.discord_channel_id:
            return "discord"
        return "outbox"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv_path: str | None = None) -> Settings:
        """Build and validate settings from ``env`` (or ``os.environ`` plus an optional ``.env``).

        Raises:
            ConfigError: if a value is invalid or a required secret is missing.
        """
        if env is None:
            load_dotenv(dotenv_path)
            env = os.environ
        data_dir = Path(env.get("SOAR_DATA_DIR", "data").strip() or "data")
        severity = env.get("HITL_MIN_SEVERITY", "medium").strip().lower() or "medium"
        if severity not in {"low", "medium", "high", "critical"}:
            raise ConfigError("HITL_MIN_SEVERITY must be low|medium|high|critical")
        script = env.get("REMEDIATION_SCRIPT", "").strip()
        s = cls(
            listen_host=env.get("LISTEN_HOST", "").strip() or cls.listen_host,
            listen_port=_int(env, "LISTEN_PORT", 8080, minimum=1),
            public_base_url=env.get("PUBLIC_BASE_URL", "").strip().rstrip("/"),
            max_body_bytes=_int(env, "MAX_BODY_BYTES", 256 * 1024, minimum=1024),
            database_path=Path(env.get("SOAR_DATABASE_PATH", "").strip() or data_dir / "soar.db"),
            data_dir=data_dir,
            webhook_secret=env.get("WEBHOOK_SHARED_SECRET", "").strip(),
            api_token=env.get("SOAR_API_TOKEN", "").strip(),
            slack_bot_token=env.get("SLACK_BOT_TOKEN", "").strip(),
            slack_signing_secret=env.get("SLACK_SIGNING_SECRET", "").strip(),
            slack_channel=env.get("SLACK_CHANNEL_ID", "").strip(),
            slack_approver_ids=_csv(env, "SLACK_APPROVER_IDS"),
            discord_bot_token=env.get("DISCORD_BOT_TOKEN", "").strip(),
            discord_public_key=env.get("DISCORD_PUBLIC_KEY", "").strip(),
            discord_channel_id=env.get("DISCORD_CHANNEL_ID", "").strip(),
            discord_approver_ids=_csv(env, "DISCORD_APPROVER_IDS"),
            approval_ttl_s=_int(env, "HITL_APPROVAL_TTL_S", 3600, minimum=60),
            expiry_sweep_s=_int(env, "HITL_EXPIRY_SWEEP_S", 30, minimum=1),
            min_severity_for_approval=severity,
            remediation_script=Path(script) if script else cls.remediation_script,
            remediation_timeout_s=_int(env, "REMEDIATION_TIMEOUT_S", 60, minimum=1),
            dry_run=_bool(env, "DRY_RUN", False),
            abuseipdb_api_key=env.get("ABUSEIPDB_API_KEY", "").strip(),
            intel_timeout_s=_int(env, "INTEL_TIMEOUT_S", 10, minimum=1),
            decision_webhook_url=env.get("DECISION_WEBHOOK_URL", "").strip(),
            decision_webhook_secret=env.get("DECISION_WEBHOOK_SECRET", "").strip(),
        )
        s.validate()
        return s

    def validate(self) -> None:
        """Refuse to start without the secrets that keep intake and approvals authenticated.

        Raises:
            ConfigError: describing the first missing or weak setting.
        """
        if not self.webhook_secret or len(self.webhook_secret) < 32:
            raise ConfigError("WEBHOOK_SHARED_SECRET must be set (>= 32 chars); the alert intake refuses "
                              "unauthenticated requests")
        if self.chat_mode == "slack" and not self.slack_signing_secret:
            raise ConfigError("SLACK_SIGNING_SECRET is required with SLACK_BOT_TOKEN (button callbacks are verified)")
        if self.chat_mode == "discord" and not self.discord_public_key:
            raise ConfigError("DISCORD_PUBLIC_KEY is required with DISCORD_BOT_TOKEN")
        if self.chat_mode == "slack" and not self.slack_approver_ids:
            raise ConfigError("SLACK_APPROVER_IDS must list the Slack user IDs allowed to approve isolation")
        if self.chat_mode == "discord" and not self.discord_approver_ids:
            raise ConfigError("DISCORD_APPROVER_IDS must list the Discord user IDs allowed to approve isolation")
        if self.decision_webhook_url:
            if not self.decision_webhook_url.startswith(("https://", "http://")):
                raise ConfigError("DECISION_WEBHOOK_URL must be an http(s) URL")
            if len(self.decision_webhook_secret) < 32:
                raise ConfigError("DECISION_WEBHOOK_SECRET must be set (>= 32 chars) when DECISION_WEBHOOK_URL is; "
                                  "receivers verify the signature")
            if self.decision_webhook_secret == self.webhook_secret:
                raise ConfigError("DECISION_WEBHOOK_SECRET must differ from WEBHOOK_SHARED_SECRET, so a receiver "
                                  "of decisions cannot forge alerts")
