from __future__ import annotations

from pathlib import Path

import pytest

from detection_rules.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
SAMPLES = ROOT / "samples"


@pytest.fixture(scope="session")
def rules():
    return load_rules(RULES)


def rule_yaml(detection: str, category: str = "process_creation", extra: str = "") -> str:
    return f"""
title: unit
id: 11111111-2222-3333-4444-555555555555
status: test
level: low
logsource: {{product: windows, category: {category}}}
tags: [attack.execution, attack.t1059.001, attack.g0016, attack.s0002]
detection:
{detection}
{extra}
"""
