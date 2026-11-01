"""Runtime settings from ``EMU_*`` / ``LAB_*`` environment variables (and an optional ``.env``)."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """An environment variable holds an invalid value."""


def _num(env: Mapping[str, str], name: str, default: float, minimum: float = 0) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


@dataclass(frozen=True)
class Settings:
    hub_url: str = "http://127.0.0.1:8000"
    hub_token: str = ""
    ingest_token: str = ""
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        default_factory=lambda: (ipaddress.ip_network("192.168.56.0/24"),))
    kube_contexts: tuple[str, ...] = ("microk8s",)
    winrm_user: str = ""
    winrm_password: str = ""
    winrm_transport: str = "ntlm"
    ssh_user: str = "vagrant"
    ssh_key: Path | None = None
    ssh_trust_lab_hostkeys: bool = False
    poll_timeout_s: float = 300
    poll_base_s: float = 2
    poll_max_s: float = 30
    window_s: float = 900
    out_dir: Path = Path("results")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv: bool = True) -> Settings:
        if env is None:
            if dotenv:
                load_dotenv(override=False)
            env = os.environ
        try:
            cidrs = tuple(ipaddress.ip_network(c.strip(), strict=False)
                          for c in env.get("LAB_ALLOWED_CIDRS", "192.168.56.0/24").split(",") if c.strip())
        except ValueError as exc:
            raise ConfigError(f"LAB_ALLOWED_CIDRS: {exc}") from exc
        if not cidrs:
            raise ConfigError("LAB_ALLOWED_CIDRS must list at least one lab network")
        for net in cidrs:
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise ConfigError(f"LAB_ALLOWED_CIDRS entry {net} is wider than a lab network should be")
        contexts = tuple(c.strip() for c in env.get("LAB_KUBE_CONTEXTS", "microk8s").split(",") if c.strip())
        key = env.get("EMU_SSH_KEY", "").strip()
        return cls(
            hub_url=env.get("EMU_HUB_URL", cls.hub_url).rstrip("/"),
            hub_token=env.get("EMU_HUB_TOKEN", ""),
            ingest_token=env.get("EMU_INGEST_TOKEN", ""),
            allowed_cidrs=cidrs,
            kube_contexts=contexts,
            winrm_user=env.get("EMU_WINRM_USER", ""),
            winrm_password=env.get("EMU_WINRM_PASSWORD", ""),
            winrm_transport=env.get("EMU_WINRM_TRANSPORT", "ntlm"),
            ssh_user=env.get("EMU_SSH_USER", "vagrant"),
            ssh_key=Path(key) if key else None,
            ssh_trust_lab_hostkeys=env.get("EMU_SSH_TRUST_LAB_HOSTKEYS", "").lower() in ("1", "true", "yes"),
            poll_timeout_s=_num(env, "EMU_POLL_TIMEOUT_S", cls.poll_timeout_s, 5),
            poll_base_s=_num(env, "EMU_POLL_BASE_S", cls.poll_base_s, 0.1),
            poll_max_s=_num(env, "EMU_POLL_MAX_S", cls.poll_max_s, 0.5),
            window_s=_num(env, "EMU_WINDOW_S", cls.window_s, 60),
            out_dir=Path(env.get("EMU_OUT_DIR", "results")),
        )
