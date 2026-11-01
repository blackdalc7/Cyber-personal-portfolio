"""DuckDB access to the Watchfloor lake: the Parquet files read-only, plus the ``ocsf_flat`` view rules run against.

The lake layout is Watchfloor's (``events/class_uid=*/dt=*/hr=*/part-*.parquet``, one flattened OCSF event per
row with the full document in ``raw``). ``ocsf_flat`` adds the columns Sigma fields map to that the lake does not
store flat, extracted from ``raw``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import duckdb

FLAT_VIEW = """
CREATE OR REPLACE VIEW ocsf_flat AS
SELECT
  uid, time, class_uid, activity_id, hostname, product, user_name, process_name, process_pid, parent_pid, cmd_line,
  coalesce(json_extract_string(raw, '$.process.file.path'), json_extract_string(raw, '$.actor.process.file.path'),
           process_name) AS process_path,
  coalesce(json_extract_string(raw, '$.process.parent_process.file.path'),
           json_extract_string(raw, '$.process.parent_process.name')) AS parent_path,
  json_extract_string(raw, '$.process.parent_process.cmd_line') AS parent_cmd_line,
  json_extract_string(raw, '$.file.path') AS target_file,
  src_ip,
  TRY_CAST(json_extract_string(raw, '$.src_endpoint.port') AS INTEGER) AS src_port,
  json_extract_string(raw, '$.dst_endpoint.ip') AS dst_ip,
  TRY_CAST(json_extract_string(raw, '$.dst_endpoint.port') AS INTEGER) AS dst_port,
  raw
FROM events
"""

# The columns of Watchfloor's lake that the view needs (a subset of watchfloor.lake.SCHEMA).
EVENT_COLUMNS = {
    "uid": "VARCHAR", "time": "BIGINT", "class_uid": "INTEGER", "activity_id": "SMALLINT", "hostname": "VARCHAR",
    "product": "VARCHAR", "user_name": "VARCHAR", "process_name": "VARCHAR", "process_pid": "BIGINT",
    "parent_pid": "BIGINT", "cmd_line": "VARCHAR", "src_ip": "VARCHAR", "raw": "VARCHAR",
}


def open_lake(lake_dir: Path) -> duckdb.DuckDBPyConnection:
    """An in-memory DuckDB with ``events`` over the lake's Parquet files (empty if there are none yet)."""
    con = duckdb.connect(":memory:")
    root = Path(lake_dir) / "events"
    if next(root.glob("class_uid=*/dt=*/hr=*/part-*.parquet"), None) is None:
        _empty_events(con)
    else:
        glob = (root / "**" / "part-*.parquet").as_posix().replace("'", "''")
        con.execute(
            "CREATE VIEW events AS SELECT * EXCLUDE (dt, hr) REPLACE (epoch_ms(time) AS time) "  # noqa: S608
            f"FROM read_parquet('{glob}', hive_partitioning = true, union_by_name = true, "
            "hive_types = {'class_uid': INTEGER, 'dt': VARCHAR, 'hr': VARCHAR})")
    con.execute(FLAT_VIEW)
    return con


def _empty_events(con: duckdb.DuckDBPyConnection) -> None:
    cols = ", ".join(f"{k} {v}" for k, v in EVENT_COLUMNS.items())
    con.execute(f"CREATE TABLE events ({cols})")


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    """The lake columns for one OCSF document, the same projection Watchfloor's lake writer stores."""
    proc = doc.get("process") or (doc.get("actor") or {}).get("process") or {}
    user = doc.get("user") or (doc.get("actor") or {}).get("user") or proc.get("user") or {}
    return {
        "uid": doc["metadata"]["uid"], "time": int(doc["time"]), "class_uid": int(doc["class_uid"]),
        "activity_id": int(doc["activity_id"]), "hostname": (doc.get("device") or {}).get("hostname"),
        "product": (doc["metadata"].get("product") or {}).get("name"), "user_name": user.get("name"),
        "process_name": proc.get("name"), "process_pid": proc.get("pid"),
        "parent_pid": (proc.get("parent_process") or {}).get("pid"), "cmd_line": proc.get("cmd_line"),
        "src_ip": (doc.get("src_endpoint") or {}).get("ip"),
        "raw": json.dumps(doc, separators=(",", ":"), sort_keys=True),
    }


def memory_lake(docs: list[dict[str, Any]]) -> duckdb.DuckDBPyConnection:
    """An in-memory lake holding ``docs``: what rule tests run against."""
    con = duckdb.connect(":memory:")
    _empty_events(con)
    rows = [flatten(d) for d in docs]
    if rows:
        cols = list(EVENT_COLUMNS)
        con.executemany(f"INSERT INTO events VALUES ({', '.join('?' for _ in cols)})",  # noqa: S608
                        [[r[c] for c in cols] for r in rows])
    con.execute(FLAT_VIEW)
    return con
