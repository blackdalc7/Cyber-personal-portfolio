"""Command line.

    alert-triage init-cmdb --seed examples/cmdb_seed.yml
    alert-triage generate --count 5000 --out examples/alerts.json
    alert-triage triage --alerts examples/alerts.json --report out/queue.md --json out/queue.json
    alert-triage evaluate --alerts examples/alerts.json --min-recall 1.0
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path

from . import generator
from .alerts import AlertFormatError, load_alerts
from .applicability import RequirementError, load_requirements
from .assess import TriageEngine
from .cluster import cluster_alerts
from .cmdb import Cmdb, CmdbError
from .config import ConfigError, Settings
from .llm import build_triager
from .report import RunInfo, evaluate, metrics, render_json, render_markdown, write

logger = logging.getLogger("alert_triage")
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REQUIREMENTS = ROOT / "config" / "signature_requirements.yml"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for ``init-cmdb``, ``generate``, ``triage`` and ``evaluate``."""
    p = argparse.ArgumentParser(prog="alert-triage", description="Alert clustering and false-positive reduction")
    p.add_argument("--env-file", default=None, help="Path to a .env file")
    p.add_argument("--db", type=Path, help="CMDB SQLite path (default: TRIAGE_DB_PATH)")
    sub = p.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init-cmdb", help="Create or replace the mock CMDB from a YAML seed")
    i.add_argument("--seed", type=Path, default=ROOT / "examples" / "cmdb_seed.yml")

    g = sub.add_parser("generate", help="Write simulated, labelled SIEM alerts")
    g.add_argument("--count", type=int, default=5000)
    g.add_argument("--seed", type=int, default=7)
    g.add_argument("--out", type=Path, required=True)

    for name, text in (("triage", "Cluster, enrich and triage alerts into a prioritised queue"),
                       ("evaluate", "Triage labelled alerts and score the result against ground truth")):
        t = sub.add_parser(name, help=text)
        t.add_argument("--alerts", type=Path, required=True, help="JSON array, {'alerts': [...]} or NDJSON")
        t.add_argument("--requirements", type=Path, default=DEFAULT_REQUIREMENTS)
        t.add_argument("--algorithm", choices=["dbscan", "kmeans"])
        t.add_argument("--eps", type=float, help="DBSCAN cosine distance threshold")
        t.add_argument("--offline", action="store_true", help="Never call the LLM, even if a key is configured")
        if name == "triage":
            t.add_argument("--report", type=Path, help="Write the Markdown report here")
            t.add_argument("--json", dest="json_out", type=Path, help="Write the JSON report here")
            t.add_argument("--fail-on-escalate", action="store_true", help="Exit 3 if anything is escalated")
        else:
            t.add_argument("--min-recall", type=float, default=1.0, help="Minimum true-threat recall (0-1)")
            t.add_argument("--min-precision", type=float, default=0.95, help="Minimum suppression precision (0-1)")
    return p


def _pipeline(args, settings: Settings):
    if args.algorithm:
        settings = replace(settings, algorithm=args.algorithm)
    if args.eps is not None:
        if not 0 < args.eps < 1:
            raise ConfigError("--eps must be between 0 and 1")
        settings = replace(settings, dbscan_eps=args.eps)
    if args.offline:
        settings = replace(settings, llm_provider="offline")
    if not settings.db_path.exists():
        raise CmdbError(f"CMDB {settings.db_path} does not exist; run 'alert-triage init-cmdb' first")

    alerts = load_alerts(args.alerts)
    applicability = load_requirements(args.requirements)
    clusters = cluster_alerts(alerts, settings.algorithm, settings.dbscan_eps, settings.time_window_s,
                              settings.kmeans_max_k)
    logger.info("%d alerts -> %d distinct documents -> %d meta-alerts", len(alerts), clusters.unique_documents,
                len(clusters.meta_alerts))
    with Cmdb(settings.db_path) as cmdb:
        triager = build_triager(settings, cache=cmdb)
        engine = TriageEngine(cmdb, applicability, triager, settings.llm_min_confidence, settings.llm_workers)
        triaged = engine.run(clusters.meta_alerts)
    run = RunInfo(
        input=str(args.alerts), algorithm=settings.algorithm, eps=settings.dbscan_eps,
        time_window_s=settings.time_window_s, llm_provider=triager.provider,
        llm_model=getattr(triager, "model", ""), minutes_per_raw_alert=settings.minutes_per_raw_alert,
        minutes_per_meta_alert=settings.minutes_per_meta_alert,
        simulated=any(a.raw.get("scenario") for a in alerts[:50]),
        llm_stats=getattr(triager, "stats", None),
    )
    return run, metrics(len(alerts), clusters, triaged, run), triaged


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (non-zero on errors or a failed quality gate)."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        settings = Settings.from_env(dotenv_path=args.env_file)
        if args.db:
            settings = replace(settings, db_path=args.db)

        if args.command == "init-cmdb":
            with Cmdb(settings.db_path) as cmdb:
                counts = cmdb.seed_file(args.seed)
            print(f"CMDB {settings.db_path}: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
            return 0

        if args.command == "generate":
            n = generator.write(args.out, args.count, args.seed)
            print(f"Wrote {n} simulated alerts to {args.out}")
            return 0

        run, m, triaged = _pipeline(args, settings)
        result = evaluate(triaged)

        if args.command == "evaluate":
            if result is None:
                raise AlertFormatError("evaluate needs labelled alerts (a 'label' field on each alert)")
            print(json.dumps({"metrics": m, "evaluation": result}, indent=2))
            failed = []
            if result["true_threat_recall"] < args.min_recall:
                failed.append(f"true-threat recall {result['true_threat_recall']} < {args.min_recall}")
            if result["suppression_precision"] < args.min_precision:
                failed.append(f"suppression precision {result['suppression_precision']} < {args.min_precision}")
            for f in failed:
                logger.error("%s", f)
            return 2 if failed else 0

        if args.report:
            write(args.report, render_markdown(run, m, triaged, result))
        if args.json_out:
            write(args.json_out, render_json(run, m, triaged, result))
        print(f"{m['raw_alerts']} alerts -> {m['meta_alerts']} meta-alerts -> queue of {m['analyst_queue']} "
              f"({m['escalate']} escalate, {m['investigate']} investigate); "
              f"{m['suppressed_alerts']} alerts suppressed; est. analyst time saved {m['analyst_time_saved_pct']}%")
        if args.fail_on_escalate and m["escalate"]:
            return 3
        return 0
    except (ConfigError, CmdbError, RequirementError, AlertFormatError, ValueError, OSError) as exc:
        logger.error("%s", exc)
        return 1
