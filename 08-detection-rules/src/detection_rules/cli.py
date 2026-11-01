"""``detection-rules build | test | convert | run``."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from functools import partial
from pathlib import Path

from . import __version__
from .config import ConfigError, Settings
from .index import build_index, write_build
from .lake import open_lake
from .rules import RuleError, compile_file, load_rules
from .runner import HubSink, PrintSink, watch
from .testing import run_rule_tests

log = logging.getLogger("detection_rules")


def _run_tests(settings: Settings, quiet: bool = False) -> tuple[list, dict, int]:
    rules = load_rules(settings.rules_dir)
    tests = {r.id: run_rule_tests(r, settings.samples_dir) for r in rules}
    failed = 0
    for r in rules:
        for t in tests[r.id]:
            failed += not t.passed
            if not quiet or not t.passed:
                mark = "ok  " if t.passed else "FAIL"
                print(f"{mark} {r.stem}: {t.name} (expected {t.expected}, got {t.got})")
    return rules, tests, failed


def cmd_test(settings: Settings, args: argparse.Namespace) -> int:
    rules, tests, failed = _run_tests(settings, quiet=args.quiet)
    total = sum(len(v) for v in tests.values())
    print(f"{len(rules)} rules, {total - failed}/{total} rule tests passed")
    return 1 if failed else 0


def cmd_build(settings: Settings, args: argparse.Namespace) -> int:
    rules, tests, failed = _run_tests(settings, quiet=True)
    out = write_build(build_index(rules, tests), rules, settings.build_dir)
    print(f"wrote {out} ({len(rules)} rules{f', {failed} failing tests' if failed else ''})")
    return 1 if failed else 0


def cmd_convert(settings: Settings, args: argparse.Namespace) -> int:
    for path in args.rules:
        rule = compile_file(path, settings.rules_dir)
        print(f"-- {rule.title} ({rule.id})\n{rule.sql};")
    return 0


def cmd_run(settings: Settings, args: argparse.Namespace) -> int:
    rules = load_rules(settings.rules_dir)
    sink = PrintSink() if args.dry_run else HubSink(settings.hub_url, settings.ingest_token)
    log.info("%d rules over %s, every %ss", len(rules), settings.lake_dir, args.interval)
    watch(rules, partial(open_lake, settings.lake_dir), sink, settings.state_file, interval_s=args.interval,
          lookback_s=settings.lookback_s, overlap_s=settings.overlap_s,
          max_per_rule=settings.max_findings_per_rule, cycles=None if args.watch else 1)
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="detection-rules", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("test", help="run every rule against its match/nomatch samples")
    t.add_argument("-q", "--quiet", action="store_true", help="only print failures")
    sub.add_parser("build", help="test, then write build/rules_index.json and build/queries/*.sql")
    c = sub.add_parser("convert", help="print the DuckDB SQL for rule files")
    c.add_argument("rules", nargs="+", type=Path)
    r = sub.add_parser("run", help="query the lake for new hits and send findings to the hub")
    r.add_argument("--watch", action="store_true", help="keep running every --interval seconds")
    r.add_argument("--interval", type=float, default=60.0)
    r.add_argument("--dry-run", action="store_true", help="print findings as NDJSON instead of sending them")
    return p


COMMANDS = {"test": cmd_test, "build": cmd_build, "convert": cmd_convert, "run": cmd_run}


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s",
                        stream=sys.stderr)
    try:
        return COMMANDS[args.cmd](Settings.from_env(), args)
    except (RuleError, ConfigError, ValueError, OSError) as exc:
        print(f"detection-rules: {exc}", file=sys.stderr)
        return 2
