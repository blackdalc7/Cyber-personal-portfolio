"""Shared pytest fixtures: seeded CMDB, requirements and an alert factory."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from alert_triage.alerts import Alert
from alert_triage.applicability import load_requirements
from alert_triage.cmdb import Cmdb

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "examples" / "cmdb_seed.yml"
REQUIREMENTS = ROOT / "config" / "signature_requirements.yml"
T0 = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def cmdb():
    db = Cmdb(":memory:")
    db.seed_file(SEED)
    yield db
    db.close()


@pytest.fixture
def requirements():
    return load_requirements(REQUIREMENTS)


_counter = iter(range(1, 10**9))


def make_alert(
    rule="ET SCAN Nmap SYN scan",
    *,
    offset_s=0,
    src="198.51.100.7",
    dst="10.20.1.10",
    port=443,
    severity="medium",
    category="exploit",
    signature=None,
    label="",
    **kw,
) -> Alert:
    return Alert(
        id=kw.pop("id", f"A{next(_counter)}"),
        timestamp=T0 + timedelta(seconds=offset_s),
        rule=rule,
        category=category,
        severity=severity,
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        protocol=kw.pop("protocol", "tcp"),
        signature=signature or rule,
        label=label,
        **kw,
    )
