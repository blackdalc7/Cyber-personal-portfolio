from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from evidence_timeline.config import Settings

ROOT = Path(__file__).resolve().parents[1]
SECRET = "e" * 40


@pytest.fixture
def settings(tmp_path):
    return replace(Settings.from_env({}, dotenv=False), shared_secret=SECRET, out_dir=tmp_path / "evidence",
                   mode="local", local_dir=ROOT / "examples" / "hayabusa")
