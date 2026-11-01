"""Settings from ``EVIDENCE_*`` environment variables (and an optional ``.env``)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


class ConfigError(ValueError):
    """An environment variable holds an invalid or unsafe value."""


# Collection is read-only triage. Anything that could change the endpoint (remediation, quarantine, file deletion,
# arbitrary command execution) is refused even if someone puts it in TRIAGE_ARTIFACTS.
SAFE_ARTIFACT = re.compile(
    r"^(Windows\.(EventLogs|System|Network|Forensics|Detection)\.[A-Za-z0-9.]+|Windows\.Sysinternals\.Autoruns"
    r"|Linux\.(Sys|Network|Forensics|Detection)\.[A-Za-z0-9.]+|Generic\.Client\.Info)$")
UNSAFE_WORDS = re.compile(r"(?i)(remediat|quarantine|delete|kill|execute|shell|powershell|upload|response)")


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
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


def check_artifact(name: str) -> str:
    if not SAFE_ARTIFACT.match(name) or UNSAFE_WORDS.search(name):
        raise ConfigError(f"artifact {name!r} is not on the read-only triage allowlist")
    return name


@dataclass(frozen=True)
class Settings:
    shared_secret: str = field(default="", repr=False)
    out_dir: Path = Path("evidence")
    mode: str = "velociraptor"  # velociraptor | local
    hub_url: str = ""
    hub_token: str = field(default="", repr=False)
    velociraptor_api_config: Path = Path("api.config.yaml")
    hayabusa_artifact: str = "Windows.EventLogs.Hayabusa"
    triage_artifacts: tuple[str, ...] = ("Windows.System.Pslist", "Windows.Network.Netstat",
                                         "Windows.Sysinternals.Autoruns")
    local_dir: Path = Path("examples/hayabusa")
    collect_timeout_s: int = 1800
    window_before_s: int = 3600
    window_after_s: int = 1800
    max_rows_per_source: int = 50_000
    listen_host: str = "127.0.0.1"
    listen_port: int = 8090

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, dotenv: bool = True) -> Settings:
        if env is None:
            if dotenv:
                load_dotenv(override=False)
            env = os.environ
        mode = env.get("EVIDENCE_MODE", cls.mode).strip().lower() or cls.mode
        triage = tuple(a.strip() for a in env.get("TRIAGE_ARTIFACTS", ",".join(cls.triage_artifacts)).split(",")
                       if a.strip())
        s = cls(
            shared_secret=env.get("EVIDENCE_SHARED_SECRET", "").strip(),
            out_dir=Path(env.get("EVIDENCE_OUT_DIR", "").strip() or cls.out_dir),
            mode=mode,
            hub_url=env.get("EVIDENCE_HUB_URL", "").strip().rstrip("/"),
            hub_token=env.get("EVIDENCE_HUB_TOKEN", "").strip(),
            velociraptor_api_config=Path(env.get("VELOCIRAPTOR_API_CONFIG", "").strip()
                                         or cls.velociraptor_api_config),
            hayabusa_artifact=env.get("HAYABUSA_ARTIFACT", "").strip() or cls.hayabusa_artifact,
            triage_artifacts=triage,
            local_dir=Path(env.get("EVIDENCE_LOCAL_DIR", "").strip() or cls.local_dir),
            collect_timeout_s=_int(env, "EVIDENCE_COLLECT_TIMEOUT_S", cls.collect_timeout_s, 60),
            window_before_s=_int(env, "EVIDENCE_WINDOW_BEFORE_S", cls.window_before_s, 0),
            window_after_s=_int(env, "EVIDENCE_WINDOW_AFTER_S", cls.window_after_s, 0),
            max_rows_per_source=_int(env, "EVIDENCE_MAX_ROWS", cls.max_rows_per_source, 100),
            listen_host=env.get("EVIDENCE_LISTEN_HOST", "").strip() or cls.listen_host,
            listen_port=_int(env, "EVIDENCE_LISTEN_PORT", cls.listen_port, 1),
        )
        s.validate()
        return s

    def validate(self) -> None:
        if self.mode not in ("velociraptor", "local"):
            raise ConfigError("EVIDENCE_MODE must be velociraptor or local")
        for a in (self.hayabusa_artifact, *self.triage_artifacts):
            check_artifact(a)
