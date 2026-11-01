"""Tests for the mock CMDB and the verdict cache."""

from datetime import datetime, timezone

import pytest

from alert_triage.cmdb import Cmdb, CmdbError


def test_seeded_lookups(cmdb):
    web = cmdb.asset("10.20.1.10")
    assert web.hostname == "web01" and web.os_family == "linux" and web.internet_facing
    assert web.listens_on(443) and not web.listens_on(3389)
    assert cmdb.asset("10.20.1.10") is web  # cached
    ctx = web.context()
    assert ctx["os"] == "linux Ubuntu 22.04" and "443/tcp https nginx 1.24" in ctx["listening_services"]
    assert cmdb.asset("10.99.0.1") is None
    assert cmdb.stats()["assets"] == 12


def test_scanners_and_maintenance(cmdb):
    assert cmdb.authorized_scanner("10.0.5.3")[0] == "secops-vuln-mgmt"
    assert cmdb.authorized_scanner("10.0.5.20") is None and cmdb.authorized_scanner("") is None
    assert cmdb.authorized_scanner("2001:db8::1") is None
    inside = datetime(2026, 10, 26, 2, 0, tzinfo=timezone.utc)
    assert "CHG-20431" in cmdb.maintenance("10.20.3.30", inside)
    assert cmdb.maintenance("10.20.3.30", datetime(2026, 10, 26, 2, 0)) is not None  # naive = UTC
    assert cmdb.maintenance("10.20.3.30", datetime(2026, 10, 26, 5, 0, tzinfo=timezone.utc)) is None


def test_reseed_replaces(cmdb):
    counts = cmdb.seed(
        {
            "assets": [
                {
                    "ip": "10.1.1.1",
                    "hostname": "h",
                    "os_family": "Windows",
                    "criticality": 1,
                    "services": [{"port": 3389}],
                }
            ],
            "maintenance_windows": [
                {"ip": "10.1.1.1", "starts_at": datetime(2026, 1, 1), "ends_at": "2026-01-02T00:00:00Z"}
            ],
        }
    )
    assert counts == {"assets": 1, "services": 1, "authorized_scanners": 0, "maintenance_windows": 1}
    assert cmdb.asset("10.20.1.10") is None and cmdb.asset("10.1.1.1").os_family == "windows"
    assert cmdb.authorized_scanner("10.0.5.3") is None


@pytest.mark.parametrize(
    "data",
    [
        {"assets": [{"hostname": "no-ip"}]},
        {"assets": [{"ip": "10.0.0.1", "os_family": "beos", "criticality": 3}]},
        {"assets": [{"ip": "10.0.0.1", "criticality": 9}]},
        {"assets": [{"ip": "10.0.0.1", "criticality": 3, "services": [{"port": 0}]}]},
        {"authorized_scanners": [{"cidr": "nope", "owner": "x"}]},
        {"maintenance_windows": [{"ip": "10.0.0.1", "starts_at": "soon", "ends_at": "later"}]},
        {"maintenance_windows": [{"ip": "10.0.0.1", "starts_at": "2026-01-02", "ends_at": "2026-01-01"}]},
    ],
)
def test_invalid_seed(data):
    with Cmdb(":memory:") as db, pytest.raises(CmdbError):
        db.seed(data)


def test_seed_file_must_be_mapping(tmp_path):
    (tmp_path / "s.yml").write_text("- a\n- b\n")
    with Cmdb(tmp_path / "sub" / "c.db") as db, pytest.raises(CmdbError, match="mapping"):
        db.seed_file(tmp_path / "s.yml")


def test_verdict_cache(tmp_path, monkeypatch):
    with Cmdb(tmp_path / "c.db") as db:
        assert db.cached_verdict("fp") is None
        db.store_verdict("fp", {"verdict": "false_positive"})
        assert db.cached_verdict("fp") == {"verdict": "false_positive"}
        monkeypatch.setattr("alert_triage.cmdb.time.time", lambda: 10**12)
        assert db.cached_verdict("fp", max_age_s=60) is None
