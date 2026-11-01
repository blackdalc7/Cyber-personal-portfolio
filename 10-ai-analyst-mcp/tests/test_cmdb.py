from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import SEED

from ai_analyst.cmdb import Cmdb, CmdbError, build_cmdb


def test_lookups(data_dir: Path) -> None:
    c = Cmdb(data_dir / "cmdb.sqlite")
    ws = c.asset(hostname="WS01")
    assert ws["ip"] == "10.30.10.31" and ws["role"] == "finance workstation" and ws["internet_facing"] is False
    assert {s["port"] for s in ws["services"]} == {135, 445}
    assert c.asset(ip="10.20.4.41")["maintenance_windows"][0]["reason"].startswith("CHG-20517")
    assert c.asset(hostname="nope") is None and c.asset() is None
    assert c.scanner("10.0.5.3")["owner"] == "secops-vuln-mgmt"
    assert c.scanner("10.0.5.99") is None and c.scanner("2001:db8::1") is None
    c.close()


def test_opened_read_only(data_dir: Path) -> None:
    c = Cmdb(data_dir / "cmdb.sqlite")
    with pytest.raises(sqlite3.OperationalError):
        c._db.execute("DELETE FROM assets")
    c.close()


def test_open_builds_from_seed_when_file_missing(tmp_path: Path) -> None:
    c = Cmdb.open(tmp_path / "missing.sqlite", SEED)
    assert c.asset(hostname="db01")["criticality"] == 5
    with pytest.raises(CmdbError, match="not found"):
        Cmdb.open(tmp_path / "missing.sqlite", None)


@pytest.mark.parametrize(("seed", "message"), [
    ({"assets": [{"ip": "not-an-ip"}]}, "assets\\[0\\]"),
    ({"authorized_scanners": [{"cidr": "10.0.0.0/8"}]}, "authorized_scanners\\[0\\]"),
    ({"maintenance_windows": [{"ip": "10.0.0.1", "starts_at": "2026-01-02T00:00:00Z",
                               "ends_at": "2026-01-01T00:00:00Z"}]}, "maintenance_windows\\[0\\]"),
    ([1, 2], "mapping"),
])
def test_bad_seed(tmp_path: Path, seed, message: str) -> None:
    with pytest.raises(CmdbError, match=message):
        build_cmdb(seed, tmp_path / "c.sqlite")
