"""Mock CMDB in SQLite: assets, listening services, authorised scanners and maintenance windows.

All queries are parameterised. The same database file also caches LLM verdicts, so a
re-run over the same meta-alerts does not pay for the same analysis twice.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    ip              TEXT PRIMARY KEY,
    hostname        TEXT NOT NULL,
    os_family       TEXT NOT NULL CHECK (os_family IN ('windows', 'linux', 'macos', 'network', 'other')),
    os_version      TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL DEFAULT '',
    criticality     INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
    internet_facing INTEGER NOT NULL DEFAULT 0 CHECK (internet_facing IN (0, 1)),
    owner           TEXT NOT NULL DEFAULT '',
    business_unit   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS services (
    ip       TEXT NOT NULL REFERENCES assets(ip) ON DELETE CASCADE,
    port     INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service  TEXT NOT NULL DEFAULT '',
    product  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS authorized_scanners (
    cidr    TEXT PRIMARY KEY,
    owner   TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT NOT NULL,
    starts_at TEXT NOT NULL,
    ends_at   TEXT NOT NULL,
    reason    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mw_ip ON maintenance_windows(ip);
CREATE TABLE IF NOT EXISTS llm_cache (
    fingerprint TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    response    TEXT NOT NULL
);
"""


class CmdbError(ValueError):
    """Raised when the CMDB seed data is invalid."""


@dataclass(frozen=True)
class Service:
    """A listening service on an asset."""
    port: int
    protocol: str
    service: str
    product: str


@dataclass(frozen=True)
class Asset:
    """One CMDB asset: identity, OS, role, criticality, exposure and listening services."""
    ip: str
    hostname: str
    os_family: str
    os_version: str
    role: str
    criticality: int
    internet_facing: bool
    owner: str
    business_unit: str
    services: tuple[Service, ...] = ()

    def listens_on(self, port: int) -> bool:
        """True if the asset has a service on ``port``."""
        return any(s.port == port for s in self.services)

    def context(self) -> dict[str, Any]:
        """Compact description of the asset for reports and the LLM payload."""
        return {"ip": self.ip, "hostname": self.hostname, "os": f"{self.os_family} {self.os_version}".strip(),
                "role": self.role, "criticality": self.criticality, "internet_facing": self.internet_facing,
                "business_unit": self.business_unit,
                "listening_services": [f"{s.port}/{s.protocol} {s.service} {s.product}".strip() for s in self.services]}


def _iso(value: Any) -> str:
    """Normalise to an ISO-8601 string with an explicit offset (naive times are taken as UTC)."""
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise CmdbError(f"invalid timestamp {value!r}") from exc
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


class Cmdb:
    """Mock CMDB in SQLite: assets, services, authorised scanners, maintenance windows and an LLM verdict cache.

    Thread-safe; asset lookups are memoised. Usable as a context manager.
    """
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.executescript(SCHEMA)
        self._asset_cache: dict[str, Asset | None] = {}
        self._scanners: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] | None = None

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._db.close()

    def __enter__(self) -> Cmdb:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- seeding ---------------------------------------------------------------
    def seed(self, data: Mapping[str, Any], replace: bool = True) -> dict[str, int]:
        """Load assets, services, scanners and maintenance windows from a dict.

        Returns the number of rows inserted per table.

        Raises:
            CmdbError: naming the first invalid entry (the transaction is rolled back).
        """
        counts = {"assets": 0, "services": 0, "authorized_scanners": 0, "maintenance_windows": 0}
        with self._lock, self._db:
            if replace:
                for table in ("services", "maintenance_windows", "authorized_scanners", "assets"):
                    self._db.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
            for i, a in enumerate(data.get("assets") or []):
                try:
                    ip = str(ipaddress.ip_address(str(a["ip"])))
                    self._db.execute(
                        "INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (ip, str(a.get("hostname", ip)), str(a.get("os_family", "other")).lower(),
                         str(a.get("os_version", "")), str(a.get("role", "")), int(a.get("criticality", 2)),
                         int(bool(a.get("internet_facing", False))), str(a.get("owner", "")),
                         str(a.get("business_unit", ""))))
                    for s in a.get("services") or []:
                        self._db.execute("INSERT INTO services VALUES (?, ?, ?, ?, ?)",
                                         (ip, int(s["port"]), str(s.get("protocol", "tcp")).lower(),
                                          str(s.get("service", "")), str(s.get("product", ""))))
                        counts["services"] += 1
                except (KeyError, ValueError, TypeError, sqlite3.IntegrityError) as exc:
                    raise CmdbError(f"assets[{i}]: {exc}") from exc
                counts["assets"] += 1
            for i, s in enumerate(data.get("authorized_scanners") or []):
                try:
                    cidr = str(ipaddress.ip_network(str(s["cidr"]), strict=False))
                    self._db.execute("INSERT INTO authorized_scanners VALUES (?, ?, ?)",
                                     (cidr, str(s["owner"]), str(s.get("purpose", ""))))
                except (KeyError, ValueError, sqlite3.IntegrityError) as exc:
                    raise CmdbError(f"authorized_scanners[{i}]: {exc}") from exc
                counts["authorized_scanners"] += 1
            for i, w in enumerate(data.get("maintenance_windows") or []):
                try:
                    starts, ends = _iso(w["starts_at"]), _iso(w["ends_at"])
                    if datetime.fromisoformat(ends) <= datetime.fromisoformat(starts):
                        raise ValueError("ends_at must be after starts_at")
                    self._db.execute(
                        "INSERT INTO maintenance_windows (ip, starts_at, ends_at, reason) VALUES (?, ?, ?, ?)",
                        (str(ipaddress.ip_address(str(w["ip"]))), starts, ends, str(w.get("reason", ""))))
                except (KeyError, ValueError) as exc:
                    raise CmdbError(f"maintenance_windows[{i}]: {exc}") from exc
                counts["maintenance_windows"] += 1
        self._asset_cache.clear()
        self._scanners = None
        return counts

    def seed_file(self, path: str | Path) -> dict[str, int]:
        """Seed the CMDB from a YAML file. See :meth:`seed`."""
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, Mapping):
            raise CmdbError(f"{path}: expected a mapping")
        return self.seed(data)

    # -- queries ---------------------------------------------------------------
    def asset(self, ip: str) -> Asset | None:
        """Return the asset with this IP (with its services), or ``None`` if unknown."""
        if ip in self._asset_cache:
            return self._asset_cache[ip]
        with self._lock:
            row = self._db.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
            svcs = self._db.execute("SELECT port, protocol, service, product FROM services WHERE ip = ? ORDER BY port",
                                    (ip,)).fetchall() if row else []
        asset = None if row is None else Asset(
            ip=row["ip"], hostname=row["hostname"], os_family=row["os_family"], os_version=row["os_version"],
            role=row["role"], criticality=row["criticality"], internet_facing=bool(row["internet_facing"]),
            owner=row["owner"], business_unit=row["business_unit"],
            services=tuple(Service(r["port"], r["protocol"], r["service"], r["product"]) for r in svcs))
        self._asset_cache[ip] = asset
        return asset

    def authorized_scanner(self, ip: str) -> tuple[str, str] | None:
        """(owner, purpose) if ip is inside an authorised scanner range."""
        if not ip:
            return None
        if self._scanners is None:
            with self._lock:
                rows = self._db.execute("SELECT cidr, owner, purpose FROM authorized_scanners").fetchall()
            self._scanners = [(ipaddress.ip_network(r["cidr"]), r["owner"], r["purpose"]) for r in rows]
        addr = ipaddress.ip_address(ip)
        for net, owner, purpose in self._scanners:
            if addr.version == net.version and addr in net:
                return owner, purpose
        return None

    def maintenance(self, ip: str, at: datetime) -> str | None:
        """Reason of a maintenance window covering ``at`` for ``ip``, if any."""
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        with self._lock:
            rows = self._db.execute("SELECT starts_at, ends_at, reason FROM maintenance_windows WHERE ip = ?",
                                    (ip,)).fetchall()
        for r in rows:
            if datetime.fromisoformat(r["starts_at"]) <= at <= datetime.fromisoformat(r["ends_at"]):
                return r["reason"] or "maintenance window"
        return None

    def stats(self) -> dict[str, int]:
        """Row counts for every table."""
        with self._lock:
            return {t: self._db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # noqa: S608 - fixed names
                    for t in ("assets", "services", "authorized_scanners", "maintenance_windows", "llm_cache")}

    # -- LLM verdict cache -------------------------------------------------------
    def cached_verdict(self, fingerprint: str, max_age_s: float = 7 * 86400) -> dict[str, Any] | None:
        """Return a cached LLM response for ``fingerprint`` if it is younger than ``max_age_s``."""
        with self._lock:
            row = self._db.execute("SELECT created_at, response FROM llm_cache WHERE fingerprint = ?",
                                   (fingerprint,)).fetchone()
        if row is None or time.time() - row["created_at"] > max_age_s:
            return None
        return json.loads(row["response"])

    def store_verdict(self, fingerprint: str, response: Mapping[str, Any]) -> None:
        """Cache an LLM response under ``fingerprint``."""
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?, ?, ?)",
                             (fingerprint, time.time(), json.dumps(response)))
