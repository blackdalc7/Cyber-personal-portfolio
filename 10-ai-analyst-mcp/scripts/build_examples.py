"""Write examples/output/*.json: the analyst's transcripts for Watchfloor's recorded scenarios.

Loads every scenario in ../watchfloor/datasets/scenarios into a temporary lake, builds the CMDB from
examples/cmdb_seed.yml and investigates each incident with the chosen provider (offline by default). The console's
Analyst page and the GitHub Pages demo read these files.

    python scripts/build_examples.py [--provider offline|anthropic|ollama]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ai_analyst.cmdb import Cmdb, build_cmdb
from ai_analyst.config import Settings
from ai_analyst.engine import investigate, write_transcript
from ai_analyst.lake import LakeReader, read_ndjson, write_lake
from ai_analyst.providers import make_provider
from ai_analyst.tools import Toolbox, build_server

SCENARIOS = ROOT.parent / "watchfloor" / "datasets" / "scenarios"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--provider", default="offline", choices=["offline", "anthropic", "ollama"])
    ap.add_argument("--out", type=Path, default=ROOT / "examples" / "output")
    args = ap.parse_args()
    settings = replace(Settings.from_env(), provider=args.provider)
    with tempfile.TemporaryDirectory(prefix="analyst-examples-") as tmp:
        docs = [d for f in sorted(SCENARIOS.glob("*/events.ndjson")) for d in read_ndjson(f)]
        write_lake(docs, Path(tmp) / "lake")
        build_cmdb(ROOT / "examples" / "cmdb_seed.yml", Path(tmp) / "cmdb.sqlite")
        box = Toolbox(LakeReader(Path(tmp) / "lake"), Cmdb(Path(tmp) / "cmdb.sqlite"), settings.max_rows)
        server = build_server(box)
        for inc in box.list_incidents(None, 50)["incidents"]:
            # A fixed clock two minutes after detection keeps the committed files stable between runs.
            fixed = inc["detected_at_ms"] / 1000 + 120
            doc = investigate(inc["id"], box, server, make_provider(settings), settings.max_tool_calls,
                              now=lambda fixed=fixed: fixed)
            doc["incident_status"] = inc["status"]
            path = write_transcript(doc, args.out)
            print(f"{inc['id']}: {doc['verdict']} ({doc['confidence']}), {len(doc['tool_calls'])} calls, "
                  f"citations {'valid' if doc['citations_valid'] else 'INVALID'} -> {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
