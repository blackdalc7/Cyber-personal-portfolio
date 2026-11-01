"""Configuration from environment variables / .env. The NVD API key is read here and never logged."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when an environment variable holds an invalid value."""


def _float(env: Mapping[str, str], name: str, default: float, lo: float, hi: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _int(env: Mapping[str, str], name: str, default: int, lo: int, hi: int) -> int:
    value = _float(env, name, default, lo, hi)
    if value != int(value):
        raise ConfigError(f"{name} must be an integer")
    return int(value)


@dataclass(frozen=True)
class Settings:
    """Feed endpoints, cache settings and scoring policy, loaded by :meth:`from_env`."""
    nvd_api_key: str = field(default="", repr=False)
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    http_timeout_s: float = 30.0
    cache_path: Path = Path(".cache/vuln_scanner.sqlite")
    cache_ttl_s: int = 86_400
    offline: bool = False

    # Scoring policy
    kev_likelihood_floor: float = 0.7      # a KEV entry is exploited in the wild, whatever EPSS says
    exploitable_threshold: float = 0.1     # likelihood at which a service counts as a pivot in the attack graph
    max_hops: int = 4                      # blast-radius search depth from a compromised host
    hop_decay: float = 0.5                 # each extra hop halves a target's contribution

    @property
    def nvd_delay_s(self) -> float:
        """Seconds to wait between NVD requests to stay under its public rate limits."""
        # NVD: 5 requests / 30 s without a key, 50 / 30 s with one. Stay just under both.
        return 0.65 if self.nvd_api_key else 6.5

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv_path: str | None = None) -> Settings:
        """Build settings from ``env`` (or ``os.environ`` plus an optional ``.env`` file).

        Raises:
            ConfigError: if a value is invalid.
        """
        if env is None:
            load_dotenv(dotenv_path)
            env = os.environ
        offline_raw = env.get("VULN_OFFLINE", "").strip().lower()
        if offline_raw not in {"", "0", "1", "true", "false", "yes", "no"}:
            raise ConfigError("VULN_OFFLINE must be a boolean")
        return cls(
            nvd_api_key=env.get("NVD_API_KEY", "").strip(),
            nvd_url=env.get("NVD_API_URL", "").strip() or cls.nvd_url,
            epss_url=env.get("EPSS_API_URL", "").strip() or cls.epss_url,
            kev_url=env.get("KEV_FEED_URL", "").strip() or cls.kev_url,
            http_timeout_s=_float(env, "VULN_HTTP_TIMEOUT_S", 30.0, 1, 300),
            cache_path=Path(env.get("VULN_CACHE_PATH", "").strip() or cls.cache_path),
            cache_ttl_s=_int(env, "VULN_CACHE_TTL_S", 86_400, 0, 30 * 86_400),
            offline=offline_raw in {"1", "true", "yes"},
            kev_likelihood_floor=_float(env, "VULN_KEV_FLOOR", 0.7, 0, 1),
            exploitable_threshold=_float(env, "VULN_EXPLOITABLE_THRESHOLD", 0.1, 0, 1),
            max_hops=_int(env, "VULN_MAX_HOPS", 4, 1, 16),
            hop_decay=_float(env, "VULN_HOP_DECAY", 0.5, 0.05, 1),
        )
