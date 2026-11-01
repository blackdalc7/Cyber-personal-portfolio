"""The full loop against the real hub, lake writer and 08's rules (skipped when the sibling projects are absent)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SIBLINGS = [ROOT.parent / "watchfloor" / "backend" / "src", ROOT.parent / "08-detection-rules" / "src"]
NEEDS = ("fastapi", "fakeredis", "pyarrow", "duckdb", "sigma")
missing = [m for m in NEEDS if importlib.util.find_spec(m) is None] + [str(p) for p in SIBLINGS if not p.is_dir()]
pytestmark = pytest.mark.skipif(bool(missing), reason=f"purple loop needs {', '.join(missing)}")


def test_replay_demo_scores_every_outcome(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "scripts"))
    import purple_loop

    from attack_emulator.executors import base
    monkeypatch.setattr(purple_loop.replay_mod, "now_ms", base.now_ms)  # restored after the test
    doc = purple_loop.run(ROOT / "campaigns" / "replay-demo.yml", tmp_path / "out", tmp_path / "work")
    outcomes = {c["technique"]: c["outcome"] for c in doc["results"]}
    assert outcomes == {
        "T1003.008": "detected", "T1136.001": "detected", "T1053.003": "detected", "T1059.001": "detected",
        "T1036.003": "detected", "T1070.003": "telemetry_only", "T1087.001": "telemetry_only", "T1562.001": "missed",
    }
    shadow = next(c for c in doc["results"] if c["technique"] == "T1003.008")
    assert shadow["findings"][0]["product"] == "detection-rules"
    assert shadow["findings"][0]["title"].startswith("Read of /etc/shadow")
    assert doc["summary"]["detection_coverage"] == 62.5
