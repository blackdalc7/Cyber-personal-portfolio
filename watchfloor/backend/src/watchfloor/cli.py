"""``python -m watchfloor <command>``: run the spine services or work with datasets.

Commands
--------
hub            serve the FastAPI hub (and the built UI if WF_UI_DIR is set)
ingest         run the lake writer (Redis Streams consumer group → Parquet)
adapters       tail 01/03 NDJSON, watch 06's queue.json and poll 02's API onto the spine
replay ID      publish a recorded scenario onto the spine, time-compressed
load ID|all    write recorded scenarios straight into the lake (no Redis needed)
export-demo    write the static JSON for the GitHub Pages demo
validate FILE  check every line of an NDJSON file against the OCSF contract
compact        merge small Parquet files in closed hours
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import ocsf
from .config import Settings

logger = logging.getLogger("watchfloor")


def _bus(settings: Settings):
    from .bus import EventBus

    return EventBus.from_url(settings.redis_url, stream=settings.stream, dead_letter=settings.dead_letter_stream,
                             maxlen=settings.stream_maxlen)


def cmd_hub(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    from .hub.app import create_app

    bus = None
    try:
        bus = _bus(settings)
        bus.r.ping()
    except Exception as exc:  # noqa: BLE001 - the hub still serves the lake read-only without Redis
        logger.warning("Redis unavailable (%s); live stream and ingest are disabled", exc)
        bus = None
    uvicorn.run(create_app(settings, bus=bus), host=args.host, port=args.port, log_level="info",
                proxy_headers=False)
    return 0


def cmd_ingest(args: argparse.Namespace, settings: Settings) -> int:
    from .ingest import IngestService
    from .lake import LakeWriter

    svc = IngestService(_bus(settings), LakeWriter(settings.lake_dir, settings.flush_rows),
                        consumer=args.consumer, flush_interval_s=settings.flush_interval_s)
    try:
        svc.run()
    except KeyboardInterrupt:
        svc.stop()
        svc.flush()
    return 0


def cmd_adapters(args: argparse.Namespace, settings: Settings) -> int:
    """Poll every configured source (SIEM, EDR, triage queue, SOAR) and publish its new events to the bus."""
    from .adapters import AdapterState, NdjsonTailer, QueueFileWatcher, SoarPoller

    bus = _bus(settings)
    state = AdapterState(settings.adapter_state)
    pollers = []
    if settings.siem_dir:
        pollers += [NdjsonTailer(settings.siem_dir / f"{n}.ndjson", "siem", bus, state)
                    for n in ("events", "alerts", "chains")]
    if settings.edr_alerts:
        pollers.append(NdjsonTailer(settings.edr_alerts, "edr", bus, state))
    if settings.triage_queue:
        pollers.append(QueueFileWatcher(settings.triage_queue, bus, state))
    if settings.soar_url and settings.soar_token:
        pollers.append(SoarPoller(settings.soar_url, settings.soar_token, bus, state))
    if not pollers:
        logger.error("No adapters configured: set WF_SIEM_DIR, WF_EDR_ALERTS, WF_TRIAGE_QUEUE or WF_SOAR_URL")
        return 2
    logger.info("Running %d adapters every %ss", len(pollers), settings.poll_interval_s)
    while True:
        for p in pollers:
            try:
                n = p.poll()
                if n:
                    logger.info("%s published %d events", type(p).__name__, n)
            except Exception:  # one broken source must not stop the others
                logger.exception("%s failed", type(p).__name__)
        if args.once:
            return 0
        time.sleep(settings.poll_interval_s)


def cmd_replay(args: argparse.Namespace, settings: Settings) -> int:
    from .scenarios import load_scenario, replay

    sc = load_scenario(settings.scenarios_dir / args.scenario)
    bus = _bus(settings)
    n = replay(sc, bus.publish, speed=args.speed, rebase_to_now=not args.keep_time)
    print(f"Replayed {n} events from {sc.id}")
    return 0


def cmd_load(args: argparse.Namespace, settings: Settings) -> int:
    from .lake import LakeWriter
    from .scenarios import list_scenarios, load_scenario

    writer = LakeWriter(settings.lake_dir)
    items = list_scenarios(settings.scenarios_dir) if args.scenario == "all" else [
        load_scenario(settings.scenarios_dir / args.scenario)]
    for sc in items:
        writer.add_many(ocsf.validate(e) for e in sc.events())
    writer.flush()
    print(f"Loaded {writer.rows_written} events from {len(items)} scenario(s) into {settings.lake_dir}")
    return 0


def cmd_export_demo(args: argparse.Namespace, settings: Settings) -> int:
    from .demo import export_demo

    manifest = export_demo(Path(args.out), settings.scenarios_dir, exposure_file=settings.exposure_file,
                           coverage_dir=settings.coverage_dir, triage_queue=settings.triage_queue,
                           rules_index=settings.rules_index, evidence_dir=settings.evidence_dir,
                           analyst_dir=settings.analyst_dir)
    print(json.dumps(manifest, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace, settings: Settings) -> int:
    bad = 0
    total = 0
    with open(args.file, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            total += 1
            try:
                ocsf.validate(json.loads(line))
            except (ValueError, ocsf.ContractError) as exc:
                bad += 1
                print(f"line {n}: {exc}", file=sys.stderr)
    print(f"{total - bad}/{total} events satisfy the OCSF {ocsf.OCSF_VERSION} contract")
    return 1 if bad else 0


def cmd_compact(args: argparse.Namespace, settings: Settings) -> int:
    from .lake import LakeWriter

    print(f"Compacted {LakeWriter(settings.lake_dir).compact(older_than_s=args.older_than)} partitions")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="watchfloor", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    h = sub.add_parser("hub")
    h.add_argument("--host", default="127.0.0.1")
    h.add_argument("--port", type=int, default=8000)
    h.set_defaults(fn=cmd_hub)
    i = sub.add_parser("ingest")
    i.add_argument("--consumer", default="writer-1")
    i.set_defaults(fn=cmd_ingest)
    a = sub.add_parser("adapters")
    a.add_argument("--once", action="store_true", help="poll every source once and exit")
    a.set_defaults(fn=cmd_adapters)
    r = sub.add_parser("replay")
    r.add_argument("scenario")
    r.add_argument("--speed", type=float, default=60.0, help="time compression factor (0 = no waiting)")
    r.add_argument("--keep-time", action="store_true", help="keep the recorded timestamps")
    r.set_defaults(fn=cmd_replay)
    ld = sub.add_parser("load")
    ld.add_argument("scenario", help="scenario id, or 'all'")
    ld.set_defaults(fn=cmd_load)
    e = sub.add_parser("export-demo")
    e.add_argument("--out", default="../frontend/public/demo")
    e.set_defaults(fn=cmd_export_demo)
    v = sub.add_parser("validate")
    v.add_argument("file")
    v.set_defaults(fn=cmd_validate)
    c = sub.add_parser("compact")
    c.add_argument("--older-than", type=int, default=3600)
    c.set_defaults(fn=cmd_compact)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.fn(args, Settings.from_env())
