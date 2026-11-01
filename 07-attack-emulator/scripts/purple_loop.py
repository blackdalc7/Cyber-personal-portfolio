"""The whole purple-team loop in one process, no Docker or lab needed:

    07 replays recorded telemetry -> Watchfloor hub /api/ingest/ocsf -> Redis stream (fakeredis) -> lake writer
    -> Parquet lake -> 08's Sigma rules (DuckDB) -> findings back through the hub -> 07 polls /api/findings -> score

Every component is the real code; only Redis is faked and time is virtual (each poll back-off "sleep" advances a
clock and runs one lake flush plus one rules cycle, the way the containers would in the background). Writes the
emulation-run JSON, Navigator layer and Markdown to examples/output/ (or --out).

    python scripts/purple_loop.py [--campaign campaigns/replay-demo.yml] [--out examples/output]

Needs the sibling projects importable: ../watchfloor/backend/src and ../08-detection-rules/src (added below), and
their requirements (fastapi, fakeredis, pyarrow, duckdb, pysigma).
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PORTFOLIO = ROOT.parent
for p in (ROOT / "src", PORTFOLIO / "watchfloor" / "backend" / "src", PORTFOLIO / "08-detection-rules" / "src"):
    sys.path.insert(0, str(p))

import fakeredis  # noqa: E402
from detection_rules.lake import open_lake  # noqa: E402
from detection_rules.rules import load_rules  # noqa: E402
from detection_rules.runner import HubSink, State, run_cycle  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from watchfloor.bus import EventBus  # noqa: E402
from watchfloor.config import Settings as HubSettings  # noqa: E402
from watchfloor.hub.app import create_app  # noqa: E402
from watchfloor.ingest import IngestService  # noqa: E402
from watchfloor.lake import LakeWriter  # noqa: E402

from attack_emulator.campaign import load_campaign  # noqa: E402
from attack_emulator.config import Settings  # noqa: E402
from attack_emulator.executors import replay as replay_mod  # noqa: E402
from attack_emulator.executors.replay import ReplayExecutor  # noqa: E402
from attack_emulator.poller import HubClient  # noqa: E402
from attack_emulator.report import run_doc, write_outputs  # noqa: E402
from attack_emulator.runner import new_run_id, run_campaign  # noqa: E402

INGEST, READ = "demo-ingest-token-0123456789", "demo-read-token-0123456789"
log = logging.getLogger("purple_loop")


class VirtualClock:
    def __init__(self, start: float) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t


def run(campaign_path: Path, out_dir: Path, workdir: Path) -> dict[str, Any]:
    lake = workdir / "lake"
    bus = EventBus(fakeredis.FakeRedis(decode_responses=True))
    hub = TestClient(create_app(replace(HubSettings(), lake_dir=lake, ingest_token=INGEST, hub_token=READ), bus=bus))
    for name in ("httpx", "httpx2"):  # one line per request drowns the result
        logging.getLogger(name).setLevel(logging.WARNING)
    writer = IngestService(bus, LakeWriter(lake, flush_rows=1), flush_interval_s=0)
    rules = load_rules(PORTFOLIO / "08-detection-rules" / "rules")
    sink = HubSink("http://testserver", INGEST, client=hub)
    rules_state = State()
    clock = VirtualClock(time.time())

    def pump() -> None:
        while writer.step(block_ms=1):
            pass
        writer.flush()

    def background(seconds: float) -> None:
        """What the lake writer and the rules container do while the emulator waits."""
        clock.t += seconds
        pump()
        con = open_lake(lake)
        try:
            run_cycle(rules, con, sink, rules_state, now_ms=int(clock() * 1000), lookback_s=3600, overlap_s=900)
        finally:
            con.close()
        pump()  # the findings just sent go through the same stream into the lake

    replay_mod.now_ms = lambda: int(clock() * 1000)  # replayed events land on the virtual timeline
    settings = replace(Settings.from_env({}, dotenv=False), hub_url="http://testserver", hub_token=READ,
                       ingest_token=INGEST, poll_timeout_s=60, poll_base_s=2, poll_max_s=8)
    campaign = load_campaign(campaign_path)
    run_id = new_run_id()
    replay = ReplayExecutor(settings.hub_url, INGEST, ROOT / "tests" / "fixtures" / "replay", run_id, client=hub)
    result = run_campaign(campaign, settings, {"replay": replay}, HubClient(settings.hub_url, READ, client=hub),
                          run_id=run_id, sleep=background, clock=clock)
    doc = run_doc(result)
    paths = write_outputs(doc, out_dir)
    log.info("wrote %s", ", ".join(str(p) for p in paths.values()))
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--campaign", type=Path, default=ROOT / "campaigns" / "replay-demo.yml")
    ap.add_argument("--out", type=Path, default=ROOT / "examples" / "output")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    with tempfile.TemporaryDirectory() as tmp:
        doc = run(args.campaign, args.out, Path(tmp))
    s = doc["summary"]
    print(f"{doc['run_id']}: detection coverage {s['detection_coverage']}%, telemetry coverage "
          f"{s['telemetry_coverage']}%")
    for c in doc["results"]:
        ttd = f" in {c['ttd_ms'] / 1000:.1f}s" if c.get("ttd_ms") is not None else ""
        print(f"  {c['technique']:<10} {c['name']:<28} {c['outcome']}{ttd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
