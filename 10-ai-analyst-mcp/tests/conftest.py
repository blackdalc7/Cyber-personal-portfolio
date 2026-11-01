from __future__ import annotations

from pathlib import Path

import pytest

from ai_analyst.cmdb import Cmdb, build_cmdb
from ai_analyst.lake import LakeReader, read_ndjson, write_lake
from ai_analyst.tools import Toolbox, build_server

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "examples" / "cmdb_seed.yml"
MALDOC = "INC-20261026-F64AEE6E"
SSH = "INC-20261026-FB976B87"
SCANNER = "INC-20261028-5CA11E5C"


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One lake with every triage eval case, and the example CMDB."""
    d = tmp_path_factory.mktemp("data")
    docs = [doc for f in sorted((ROOT / "evals" / "cases").glob("*/events.ndjson")) for doc in read_ndjson(f)]
    write_lake(docs, d / "lake")
    build_cmdb(SEED, d / "cmdb.sqlite")
    return d


@pytest.fixture
def box(data_dir: Path) -> Toolbox:
    b = Toolbox(LakeReader(data_dir / "lake"), Cmdb(data_dir / "cmdb.sqlite"), max_rows=100)
    yield b
    b.lake.close()
    b.cmdb.close()


@pytest.fixture
def server(box: Toolbox):
    return build_server(box)
