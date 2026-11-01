from __future__ import annotations

import sys
from pathlib import Path

import duckdb
import pytest

from ai_analyst import lake as lake_mod
from ai_analyst.lake import LakeReader, read_ndjson, write_lake

ROOT = Path(__file__).resolve().parents[1]
WATCHFLOOR = ROOT.parent / "watchfloor" / "backend" / "src"


def test_reader_sees_rows_with_epoch_ms_time(box) -> None:
    rows = box.lake.query("SELECT time, class_uid FROM events WHERE class_uid = 2005 ORDER BY time LIMIT 1")
    assert isinstance(rows[0]["time"], int) and rows[0]["class_uid"] == 2005


@pytest.mark.parametrize("sql", [
    "SELECT * FROM read_csv('/etc/passwd')",
    "COPY (SELECT 1) TO '/tmp/analyst-escape.csv'",
    "SET enable_external_access = true",
    "INSTALL httpfs",
    "ATTACH '/tmp/analyst-escape.db' AS x",
])
def test_reader_is_locked_down(box, sql: str) -> None:
    with pytest.raises(duckdb.Error):
        box.lake.query(sql)


def test_empty_lake_then_files_appear(tmp_path: Path) -> None:
    reader = LakeReader(tmp_path)
    assert reader.query("SELECT count(*) AS n FROM events")[0]["n"] == 0
    write_lake(read_ndjson(ROOT / "evals" / "cases" / "lone-low-signal" / "events.ndjson"), tmp_path)
    assert reader.query("SELECT count(*) AS n FROM events")[0]["n"] == 3
    reader.close()


@pytest.mark.skipif(not (WATCHFLOOR / "watchfloor" / "lake.py").exists(), reason="watchfloor sources not present")
def test_flatten_and_schema_match_watchfloor() -> None:
    """The analyst reads Watchfloor's lake; its test-lake writer must produce exactly what Watchfloor writes."""
    pytest.importorskip("pyarrow")
    sys.path.insert(0, str(WATCHFLOOR))
    try:
        from watchfloor import lake as wf_lake
        from watchfloor import ocsf as wf_ocsf
    finally:
        sys.path.remove(str(WATCHFLOOR))
    assert lake_mod.SCHEMA.equals(wf_lake.SCHEMA)
    for f in sorted((ROOT / "evals").glob("*/*/events.ndjson")):
        for doc in read_ndjson(f):
            assert lake_mod.flatten(doc) == wf_ocsf.flatten(doc)
