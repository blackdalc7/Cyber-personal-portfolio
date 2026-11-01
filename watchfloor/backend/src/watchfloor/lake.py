"""The Parquet lake: columnar history of every OCSF event, queried with DuckDB.

Layout (Hive partitioning, so DuckDB prunes by class and date without opening files)::

    lake/events/class_uid=2004/dt=2026-10-26/hr=11/part-<epoch>-<rand>.parquet

DuckDB allows a single writer per database, so the design keeps writes and reads
apart: :class:`LakeWriter` (only the ingest service) appends immutable Parquet files,
and :class:`LakeReader` (hub, MCP server, detection runner) opens an in-memory DuckDB
that only *reads* those files. :meth:`LakeWriter.compact` merges the many small files a
streaming writer produces into one file per closed hour.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from . import ocsf

logger = logging.getLogger("watchfloor.lake")

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
COLUMNS = [f.name for f in SCHEMA] + ["class_uid"]


def _partition(row: dict[str, Any]) -> tuple[int, str, str]:
    dt = datetime.fromtimestamp(row["time"] / 1000, tz=timezone.utc)
    return row["class_uid"], dt.strftime("%Y-%m-%d"), dt.strftime("%H")


class LakeWriter:
    """Buffer flattened events and write them as Parquet files, partitioned by class/day/hour.

    Thread-safe. Files are written to a temporary name and renamed, so readers never
    see a half-written file.
    """

    def __init__(self, root: Path, flush_rows: int = 2_000) -> None:
        self.root = Path(root) / "events"
        self.root.mkdir(parents=True, exist_ok=True)
        self.flush_rows = flush_rows
        self._buf: dict[tuple[int, str, str], list[dict[str, Any]]] = defaultdict(list)
        self._lock = threading.Lock()
        self.rows_written = 0

    def add(self, doc: dict[str, Any]) -> None:
        """Buffer one OCSF event (already validated); flushes automatically at ``flush_rows``."""
        row = ocsf.flatten(doc)
        with self._lock:
            self._buf[_partition(row)].append(row)
            pending = sum(len(v) for v in self._buf.values())
        if pending >= self.flush_rows:
            self.flush()

    def add_many(self, docs: Iterable[dict[str, Any]]) -> None:
        """Buffer several events."""
        for doc in docs:
            self.add(doc)

    def pending(self) -> int:
        """Number of buffered rows not yet on disk."""
        with self._lock:
            return sum(len(v) for v in self._buf.values())

    def flush(self) -> list[Path]:
        """Write every buffered partition to a new Parquet file; returns the files written."""
        with self._lock:
            buf, self._buf = self._buf, defaultdict(list)
        written = []
        for (class_uid, day, hour), rows in buf.items():
            written.append(self._write(class_uid, day, hour, rows))
        return written

    def _dir(self, class_uid: int, day: str, hour: str) -> Path:
        return self.root / f"class_uid={class_uid}" / f"dt={day}" / f"hr={hour}"

    def _write(self, class_uid: int, day: str, hour: str, rows: list[dict[str, Any]]) -> Path:
        directory = self._dir(class_uid, day, hour)
        directory.mkdir(parents=True, exist_ok=True)
        cols = {name: [r.get(name) for r in rows] for name in SCHEMA.names}
        table = pa.Table.from_pydict(cols, schema=SCHEMA)
        name = f"part-{time.time_ns()}-{secrets.token_hex(4)}.parquet"
        tmp = directory / f".{name}.tmp"
        pq.write_table(table, tmp, compression="zstd")
        final = directory / name
        os.replace(tmp, final)
        self.rows_written += len(rows)
        return final

    def compact(self, older_than_s: int = 3600, now: float | None = None) -> int:
        """Merge the part files of each closed hour into one file. Returns partitions compacted.

        A partition is closed when its hour ended more than ``older_than_s`` seconds ago,
        so a streaming writer never races with compaction.
        """
        now = now if now is not None else time.time()
        merged = 0
        for hr_dir in sorted(self.root.glob("class_uid=*/dt=*/hr=*")):
            parts = sorted(hr_dir.glob("part-*.parquet"))
            if len(parts) < 2:
                continue
            day = hr_dir.parent.name.split("=", 1)[1]
            hour = int(hr_dir.name.split("=", 1)[1])
            end = datetime.strptime(day, "%Y-%m-%d").replace(hour=hour, tzinfo=timezone.utc).timestamp() + 3600
            if now - end < older_than_s:
                continue
            table = pa.concat_tables([pq.read_table(p, schema=SCHEMA) for p in parts]).sort_by("time")
            name = f"part-{time.time_ns()}-compact.parquet"
            tmp = hr_dir / f".{name}.tmp"
            pq.write_table(table, tmp, compression="zstd")
            os.replace(tmp, hr_dir / name)
            for p in parts:
                p.unlink()
            merged += 1
        return merged


class LakeReader:
    """Read-only DuckDB view over the lake.

    The ``events`` view exposes ``time`` as epoch milliseconds (BIGINT), the same unit as
    the OCSF ``time`` attribute, so callers never deal with time-zone conversions.

    The connection is in-memory and only ever runs the parameterised queries in this
    module (and :mod:`watchfloor.hub.queries`); callers never pass SQL text through.
    """

    def __init__(self, root: Path) -> None:
        import duckdb

        self.root = Path(root) / "events"
        self.root.mkdir(parents=True, exist_ok=True)
        self._duckdb = duckdb
        self._lock = threading.Lock()
        self.con = duckdb.connect(":memory:")
        self.refresh()

    def refresh(self) -> None:
        """(Re)create the ``events`` view so newly written files become visible."""
        has_files = next(self.root.glob("class_uid=*/dt=*/hr=*/part-*.parquet"), None) is not None
        with self._lock:
            if has_files:
                glob = (self.root / "**" / "part-*.parquet").as_posix().replace("'", "''")
                self.con.execute(
                    "CREATE OR REPLACE VIEW events AS SELECT * EXCLUDE (dt, hr) REPLACE (epoch_ms(time) AS time) "  # noqa: S608
                    f"FROM read_parquet('{glob}', hive_partitioning = true, union_by_name = true, "
                    "hive_types = {'class_uid': INTEGER, 'dt': VARCHAR, 'hr': VARCHAR})")
            else:
                cols = ", ".join(f"NULL::{_duck_type(f.type)} AS {f.name}" for f in SCHEMA)
                self.con.execute(f"CREATE OR REPLACE VIEW events AS SELECT {cols}, NULL::INTEGER AS class_uid "
                                 "WHERE false")

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        """Run a parameterised query against the ``events`` view and return rows as dicts."""
        with self._lock:
            cur = self.con.execute(sql, list(params))
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row, strict=True)) for row in cur.fetchall()]

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        """Run a query that returns one value."""
        rows = self.query(sql, params)
        return next(iter(rows[0].values())) if rows else None

    def close(self) -> None:
        """Close the DuckDB connection."""
        self.con.close()


def _duck_type(t: pa.DataType) -> str:
    if pa.types.is_timestamp(t):
        return "BIGINT"  # the view exposes time as epoch milliseconds
    if pa.types.is_list(t):
        return "VARCHAR[]"
    if pa.types.is_integer(t):
        return "BIGINT"
    return "VARCHAR"
