"""Read-only access to the SQLite CMDB.

The schema is 06-alert-clustering-fp-reducer's (assets, services, authorised scanners, maintenance windows), so
06's ``cmdb.sqlite`` can be used directly. The analyst opens it with ``mode=ro`` and ``PRAGMA query_only``; it can
never change the inventory it reasons about.

``build_cmdb`` creates a database from a YAML seed in the same format as 06's ``examples/cmdb_seed.yml``.
"""

from __future__ import annotations

import ipaddress
import sqlite3
import tempfile
import threading
from collections.abc import Mapping
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
"""


class CmdbError(ValueError):
    """The CMDB file or seed is missing or invalid."""


def _iso(value: Any) -> str:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def build_cmdb(seed: Mapping[str, Any] | Path, path: Path) -> dict[str, int]:
    """Create (or replace) the SQLite CMDB at ``path`` from a seed mapping or YAML file."""
    data = yaml.safe_load(Path(seed).read_text(encoding="utf-8")) if isinstance(seed, Path) else seed
    if not isinstance(data, Mapping):
        raise CmdbError("CMDB seed must be a mapping")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.unlink(missing_ok=True)
    counts = {"assets": 0, "services": 0, "authorized_scanners": 0, "maintenance_windows": 0}
    db = sqlite3.connect(tmp)
    try:
        db.executescript(SCHEMA)
        for i, a in enumerate(data.get("assets") or []):
            try:
                ip = str(ipaddress.ip_address(str(a["ip"])))
                db.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (ip, str(a.get("hostname", ip)), str(a.get("os_family", "other")).lower(),
                            str(a.get("os_version", "")), str(a.get("role", "")), int(a.get("criticality", 2)),
                            int(bool(a.get("internet_facing", False))), str(a.get("owner", "")),
                            str(a.get("business_unit", ""))))
                for s in a.get("services") or []:
                    db.execute("INSERT INTO services VALUES (?, ?, ?, ?, ?)",
                               (ip, int(s["port"]), str(s.get("protocol", "tcp")).lower(), str(s.get("service", "")),
                                str(s.get("product", ""))))
                    counts["services"] += 1
            except (KeyError, ValueError, TypeError, sqlite3.IntegrityError) as exc:
                raise CmdbError(f"assets[{i}]: {exc}") from exc
            counts["assets"] += 1
        for i, s in enumerate(data.get("authorized_scanners") or []):
            try:
                db.execute("INSERT INTO authorized_scanners VALUES (?, ?, ?)",
                           (str(ipaddress.ip_network(str(s["cidr"]), strict=False)), str(s["owner"]),
                            str(s.get("purpose", ""))))
            except (KeyError, ValueError, sqlite3.IntegrityError) as exc:
                raise CmdbError(f"authorized_scanners[{i}]: {exc}") from exc
            counts["authorized_scanners"] += 1
        for i, w in enumerate(data.get("maintenance_windows") or []):
            try:
                starts, ends = _iso(w["starts_at"]), _iso(w["ends_at"])
                if ends <= starts:
                    raise ValueError("ends_at must be after starts_at")
                db.execute("INSERT INTO maintenance_windows (ip, starts_at, ends_at, reason) VALUES (?, ?, ?, ?)",
                           (str(ipaddress.ip_address(str(w["ip"]))), starts, ends, str(w.get("reason", ""))))
            except (KeyError, ValueError) as exc:
                raise CmdbError(f"maintenance_windows[{i}]: {exc}") from exc
            counts["maintenance_windows"] += 1
        db.commit()
    finally:
        db.close()
    tmp.replace(path)
    return counts


class Cmdb:
    """Parameterised, read-only lookups."""

    def __init__(self, path: Path) -> None:
        path = Path(path)
        if not path.is_file():
            raise CmdbError(f"CMDB not found at {path}")
        self._db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA query_only = ON")
        self._lock = threading.Lock()

    @classmethod
    def open(cls, path: Path, seed: Path | None = None) -> Cmdb:
        """Open ``path``; if it does not exist but ``seed`` does, build a throwaway copy in a temp directory."""
        if Path(path).is_file() or seed is None or not Path(seed).is_file():
            return cls(path)
        tmp = Path(tempfile.mkdtemp(prefix="analyst-cmdb-")) / "cmdb.sqlite"
        build_cmdb(Path(seed), tmp)
        return cls(tmp)

    def _rows(self, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, params).fetchall()]

    def asset(self, *, ip: str | None = None, hostname: str | None = None) -> dict[str, Any] | None:
        if ip:
            rows = self._rows("SELECT * FROM assets WHERE ip = ?", (ip,))
        elif hostname:
            rows = self._rows("SELECT * FROM assets WHERE lower(hostname) = lower(?) ORDER BY ip LIMIT 1", (hostname,))
        else:
            return None
        if not rows:
            return None
        a = rows[0]
        a["internet_facing"] = bool(a["internet_facing"])
        a["services"] = self._rows("SELECT port, protocol, service, product FROM services WHERE ip = ? ORDER BY port",
                                   (a["ip"],))
        a["maintenance_windows"] = self._rows(
            "SELECT starts_at, ends_at, reason FROM maintenance_windows WHERE ip = ? ORDER BY starts_at", (a["ip"],))
        return a

    def scanner(self, ip: str) -> dict[str, Any] | None:
        addr = ipaddress.ip_address(ip)
        for r in self._rows("SELECT cidr, owner, purpose FROM authorized_scanners ORDER BY cidr", ()):
            net = ipaddress.ip_network(r["cidr"])
            if addr.version == net.version and addr in net:
                return r
        return None

    def close(self) -> None:
        self._db.close()
