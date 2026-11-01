"""Shared pytest fixtures for the real-time SIEM tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from realtime_siem.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return replace(Settings(), output_dir=tmp_path, stats_interval_s=0)
