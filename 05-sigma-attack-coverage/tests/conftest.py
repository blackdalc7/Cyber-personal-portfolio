"""Shared pytest fixtures: example rules, catalogue, exercise and events."""

from pathlib import Path

import pytest

from attack_coverage.catalog import load_catalog, load_exercise
from attack_coverage.logs import load_events
from attack_coverage.sigma import load_rules

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@pytest.fixture(scope="session")
def rules():
    return load_rules([ROOT / "rules"])


@pytest.fixture(scope="session")
def catalog():
    return load_catalog(ROOT / "techniques" / "catalog.yml")


@pytest.fixture(scope="session")
def exercise(catalog):
    return load_exercise(EXAMPLES / "exercise.yml", catalog)


@pytest.fixture(scope="session")
def events():
    return load_events(EXAMPLES / "logs" / "ws01_windows_events.xml") + load_events(
        EXAMPLES / "logs" / "srv01_auditbeat.ndjson"
    )


def rule_from(detection: dict, logsource: dict | None = None):
    from attack_coverage.sigma import SigmaRule

    return SigmaRule.from_dict(
        {
            "title": "t",
            "id": "00000000-0000-4000-8000-000000000001",
            "logsource": logsource or {"category": "process_creation", "product": "windows"},
            "detection": detection,
        }
    )
