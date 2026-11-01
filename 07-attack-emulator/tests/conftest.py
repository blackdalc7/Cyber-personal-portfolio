from __future__ import annotations

from pathlib import Path

import pytest

from attack_emulator.campaign import parse_campaign
from attack_emulator.config import Settings

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "replay"
CAMPAIGNS = ROOT / "campaigns"


def campaign_doc(**over):
    doc = {
        "name": "unit",
        "settle_s": 0,
        "targets": [
            {"name": "k8s", "executor": "kubectl", "hostname": "lab-k8s", "kube_context": "microk8s"},
            {"name": "win", "executor": "winrm", "hostname": "lab-win01", "address": "192.168.56.20"},
        ],
        "tests": [
            {"technique": "T1003.008", "name": "shadow", "tactic": "credential-access", "target": "k8s",
             "test_numbers": [1], "telemetry_match": "shadow"},
            {"technique": "T1059.001", "name": "encoded", "tactic": "execution", "target": "win",
             "test_names": ["Encoded it's"], "input_args": {"command": "Write-Host 'x'", "count": 2, "flag": True}},
        ],
    }
    doc.update(over)
    return doc


@pytest.fixture
def campaign():
    return parse_campaign(campaign_doc())


@pytest.fixture
def settings(tmp_path):
    return Settings.from_env({"EMU_HUB_URL": "http://hub.test/", "EMU_HUB_TOKEN": "read-token",
                              "EMU_INGEST_TOKEN": "ingest-token-123", "EMU_POLL_TIMEOUT_S": "10",
                              "EMU_POLL_BASE_S": "1", "EMU_POLL_MAX_S": "2", "EMU_OUT_DIR": str(tmp_path / "out")})
