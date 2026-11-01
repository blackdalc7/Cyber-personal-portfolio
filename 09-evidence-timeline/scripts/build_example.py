"""Build examples/output/<incident>/ exactly as the service would after an approval, against the real hub.

The Watchfloor hub runs in-process over a lake loaded with the maldoc-to-ransomware scenario, and the endpoint
side is the Hayabusa CSV in examples/hayabusa/ws01.csv (local mode: no Velociraptor server needed).

    python scripts/build_example.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT.parent / "watchfloor"
sys.path[:0] = [str(ROOT / "src"), str(WF / "backend" / "src")]

from fastapi.testclient import TestClient  # noqa: E402
from watchfloor.config import Settings as HubSettings  # noqa: E402
from watchfloor.hub.app import create_app  # noqa: E402
from watchfloor.lake import LakeWriter  # noqa: E402
from watchfloor.scenarios import list_scenarios  # noqa: E402

from evidence_timeline.config import Settings  # noqa: E402
from evidence_timeline.jobs import CollectRequest, collect  # noqa: E402

INCIDENT, HOST, DETECTED_MS = "INC-20261026-F64AEE6E", "ws01", 1793005226000
READ_TOKEN = "example-read-token"  # noqa: S105 - an in-process demo hub, not a credential


def main() -> int:
    out = ROOT / "examples" / "output"
    with tempfile.TemporaryDirectory() as tmp:
        lake = Path(tmp) / "lake"
        w = LakeWriter(lake)
        for sc in list_scenarios(WF / "datasets" / "scenarios"):
            w.add_many(sc.events())
        w.flush()
        hub = TestClient(create_app(replace(HubSettings(), lake_dir=lake, hub_token=READ_TOKEN)))
        settings = replace(Settings.from_env({}, dotenv=False), mode="local", local_dir=ROOT / "examples" / "hayabusa",
                           out_dir=Path(tmp) / "evidence", hub_url="http://testserver",
                           hub_token=READ_TOKEN)
        path, n = collect(CollectRequest(incident_id=INCIDENT, host=HOST, around_ms=DETECTED_MS,
                                         requested_by="n8n:watchfloor-decision", decided_by="analyst.dana",
                                         reason="Containment of ws01 approved in 02"), settings, http=hub,
                          now_ms=DETECTED_MS + 120_000)
        shutil.rmtree(out / INCIDENT, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)
        shutil.copytree(path, out / INCIDENT)
    print(f"{out / INCIDENT}: {n} timeline rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
