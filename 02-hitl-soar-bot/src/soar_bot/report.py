"""Print the MTTR report from the SQLite database.

    python -m soar_bot.report --db data/soar.db [--json] [--days 30]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .db import Database


def _fmt(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    if seconds < 120:
        return f"{seconds:.0f}s"
    if seconds < 7200:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def render(report: dict) -> str:
    """Format an MTTR report as a plain-text table."""
    lines = [f"Incidents: {report['incidents']}  by status: {report['by_status']}", ""]
    header = f"{'scope':<10} {'KPI':<20} {'n':>4} {'mean':>8} {'median':>8} {'p90':>8}"
    lines += [header, "-" * len(header)]
    scopes = [("overall", report["overall"]), *list(report["by_severity"].items())]
    for scope, kpis in scopes:
        for kpi, s in kpis.items():
            lines.append(f"{scope:<10} {kpi:<20} {s['count']:>4} {_fmt(s['mean_s']):>8} "
                         f"{_fmt(s['median_s']):>8} {_fmt(s['p90_s']):>8}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: print MTTA and MTTR from the incident database."""
    ap = argparse.ArgumentParser(description="MTTR report")
    ap.add_argument("--db", type=Path, default=Path("data/soar.db"))
    ap.add_argument("--days", type=float, help="only incidents detected in the last N days")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if not args.db.exists():
        print(f"error: database {args.db} not found", file=sys.stderr)
        return 2
    since = time.time() - args.days * 86400 if args.days else None
    report = Database(args.db).mttr_report(since)
    print(json.dumps(report, indent=2) if args.json else render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
