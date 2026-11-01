"""Read-only DuckDB access to the Watchfloor lake, plus a writer for test and eval lakes.

The lake layout and column set are Watchfloor's (``events/class_uid=*/dt=*/hr=*/part-*.parquet``). The reader is
locked down in three layers:

1. The tools in :mod:`ai_analyst.tools` only run fixed, parameterised SQL; no tool takes SQL or a path.
2. After the ``events`` view is created, DuckDB external access is switched off except for the lake directory, and
   the configuration is locked, so even an injected statement could not read ``/etc/passwd``, fetch a URL, install
   an extension or turn access back on.
3. In the stack the lake is mounted read-only.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

INCIDENT_FINDING = 2005

# Watchfloor's lake schema (watchfloor/backend/src/watchfloor/lake.py). tests/test_lake.py checks the two agree.
SCHEMA = pa.schema([
    ("time", pa.timestamp("ms", tz="UTC")),
    ("category_uid", pa.int16()),
    ("activity_id", pa.int16()),
    ("type_uid", pa.int32()),
    ("severity_id", pa.int8()),
    ("status_id", pa.int16()),
    ("uid", pa.string()),
    ("correlation_uid", pa.string()),
    ("product", pa.string()),
    ("hostname", pa.string()),
    ("src_ip", pa.string()),
    ("user_name", pa.string()),
    ("process_name", pa.string()),
    ("process_pid", pa.int64()),
    ("parent_pid", pa.int64()),
    ("cmd_line", pa.string()),
    ("file_path", pa.string()),
    ("finding_uid", pa.string()),
    ("finding_title", pa.string()),
    ("techniques", pa.list_(pa.string())),
    ("scenario", pa.string()),
    ("message", pa.string()),
    ("raw", pa.string()),
])
_EMPTY_VIEW = ("CREATE OR REPLACE VIEW events AS SELECT * FROM (VALUES (0::BIGINT, 0::INTEGER, 0::SMALLINT, "
               "0::TINYINT, 0::SMALLINT, ''::VARCHAR, ''::VARCHAR, ''::VARCHAR, ''::VARCHAR, ''::VARCHAR, "
               "''::VARCHAR, ''::VARCHAR, 0::BIGINT, 0::BIGINT, ''::VARCHAR, ''::VARCHAR, ''::VARCHAR, ''::VARCHAR, "
               "[]::VARCHAR[], ''::VARCHAR, ''::VARCHAR, ''::VARCHAR)) AS t(time, class_uid, activity_id, "
               "severity_id, status_id, uid, correlation_uid, product, hostname, src_ip, user_name, process_name, "
               "process_pid, parent_pid, cmd_line, file_path, finding_uid, finding_title, techniques, scenario, "
               "message, raw) WHERE false")


class LakeReader:
    """An in-memory DuckDB connection whose only data is the lake's ``events`` view (time as epoch ms)."""

    def __init__(self, root: Path) -> None:
        self.events_dir = Path(root).resolve() / "events"
        self._lock = threading.Lock()
        self.con = duckdb.connect(":memory:")
        self._has_files = False
        self._create_view()
        allowed = self.events_dir.as_posix().replace("'", "''") + "/"
        self.con.execute(f"SET allowed_directories = ['{allowed}']")
        self.con.execute("SET enable_external_access = false")
        self.con.execute("SET autoinstall_known_extensions = false")
        self.con.execute("SET autoload_known_extensions = false")
        self.con.execute("SET lock_configuration = true")

    def _create_view(self) -> None:
        self._has_files = self.events_dir.is_dir() and next(
            self.events_dir.glob("class_uid=*/dt=*/hr=*/part-*.parquet"), None) is not None
        if not self._has_files:
            self.con.execute(_EMPTY_VIEW)
            return
        glob = (self.events_dir / "**" / "part-*.parquet").as_posix().replace("'", "''")
        self.con.execute(
            "CREATE OR REPLACE VIEW events AS SELECT * EXCLUDE (dt, hr, category_uid, type_uid) "  # noqa: S608
            f"REPLACE (epoch_ms(time) AS time) FROM read_parquet('{glob}', hive_partitioning = true, "
            "union_by_name = true, hive_types = {'class_uid': INTEGER, 'dt': VARCHAR, 'hr': VARCHAR})")

    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Run one of the module-defined queries. The glob is re-read on every query, so new files show up."""
        with self._lock:
            if not self._has_files:
                self._create_view()
            cur = self.con.execute(sql, params or [])
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def close(self) -> None:
        self.con.close()


# --- writing (tests, evals, examples) ------------------------------------------------------------------------

def techniques_of(doc: dict[str, Any]) -> list[str]:
    info = doc.get("finding_info") or {}
    return sorted({a["technique"]["uid"] for a in info.get("attacks", []) if a.get("technique", {}).get("uid")})


def flatten(doc: dict[str, Any]) -> dict[str, Any]:
    """Watchfloor's ``ocsf.flatten``: the OCSF document projected onto the lake columns."""
    meta = doc.get("metadata", {})
    device = doc.get("device") or {}
    proc = doc.get("process") or (doc.get("actor") or {}).get("process") or {}
    user = doc.get("user") or (doc.get("actor") or {}).get("user") or proc.get("user") or {}
    file_ = doc.get("file") or proc.get("file") or {}
    info = doc.get("finding_info") or {}
    if doc.get("class_uid") == INCIDENT_FINDING and doc.get("finding_info_list"):
        info = {"uid": meta.get("correlation_uid") or meta.get("uid"), "title": doc["finding_info_list"][0]["title"]}
    labels = meta.get("labels") or []
    scenario = next((lab.split(":", 1)[1] for lab in labels if lab.startswith("scenario:")), None)
    return {
        "time": int(doc["time"]),
        "class_uid": int(doc["class_uid"]),
        "category_uid": int(doc["category_uid"]),
        "activity_id": int(doc["activity_id"]),
        "type_uid": int(doc["type_uid"]),
        "severity_id": int(doc.get("severity_id", 0)),
        "status_id": doc.get("status_id"),
        "uid": meta.get("uid"),
        "correlation_uid": meta.get("correlation_uid"),
        "product": (meta.get("product") or {}).get("name"),
        "hostname": device.get("hostname") or (doc.get("dst_endpoint") or {}).get("hostname"),
        "src_ip": (doc.get("src_endpoint") or {}).get("ip"),
        "user_name": user.get("name"),
        "process_name": proc.get("name"),
        "process_pid": proc.get("pid"),
        "parent_pid": (proc.get("parent_process") or {}).get("pid"),
        "cmd_line": proc.get("cmd_line"),
        "file_path": file_.get("path"),
        "finding_uid": info.get("uid"),
        "finding_title": info.get("title"),
        "techniques": techniques_of(doc),
        "scenario": scenario,
        "message": doc.get("message"),
        "raw": json.dumps(doc, separators=(",", ":"), ensure_ascii=False, sort_keys=True),
    }


def write_lake(docs: Iterable[dict[str, Any]], root: Path) -> int:
    """Write OCSF documents as a Watchfloor-layout lake under ``root``. Returns rows written."""
    parts: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for doc in docs:
        row = flatten(doc)
        dt = datetime.fromtimestamp(row["time"] / 1000, tz=timezone.utc)
        parts[(row["class_uid"], dt.strftime("%Y-%m-%d"), dt.strftime("%H"))].append(row)
    n = 0
    for (class_uid, day, hour), rows in parts.items():
        directory = Path(root) / "events" / f"class_uid={class_uid}" / f"dt={day}" / f"hr={hour}"
        directory.mkdir(parents=True, exist_ok=True)
        table = pa.Table.from_pydict({c: [r.get(c) for r in rows] for c in SCHEMA.names}, schema=SCHEMA)
        name = f"part-{time.time_ns()}-{secrets.token_hex(4)}.parquet"
        pq.write_table(table, directory / f".{name}.tmp", compression="zstd")
        os.replace(directory / f".{name}.tmp", directory / name)
        n += len(rows)
    return n


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
