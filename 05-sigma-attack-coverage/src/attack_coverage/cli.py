"""Command line.

    attack-coverage lint
    attack-coverage test-rules
    attack-coverage score --exercise examples/exercise.yml --logs examples/logs/*.xml examples/logs/*.ndjson
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from .catalog import CatalogError, load_catalog, load_exercise
from .coverage import evaluate, navigator_layer, to_json, to_markdown
from .logs import LogFormatError, load_events
from .ruletests import run_rule_tests
from .sigma import SigmaRuleError, load_rules

logger = logging.getLogger("attack_coverage")
ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name, "").strip()
    return Path(value) if value else default


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``lint``, ``test-rules`` and ``score`` subcommands."""
    p = argparse.ArgumentParser(prog="attack-coverage", description="Sigma-validated ATT&CK detection coverage")
    p.add_argument("--env-file", default=None, help="Path to a .env file")
    p.add_argument("--rules", type=Path, nargs="+", help="Sigma rule files or directories (default: rules/)")
    p.add_argument("--catalog", type=Path, help="Technique catalogue YAML (default: techniques/catalog.yml)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("lint", help="Validate rules, catalogue and (optionally) an exercise").add_argument(
        "--exercise", type=Path)

    t = sub.add_parser("test-rules", help="Run detection-as-code unit cases")
    t.add_argument("--cases", type=Path, help="Directory of rule test cases (default: rule-tests/)")
    t.add_argument("--require-all", action="store_true", help="Fail if any rule has no test cases")

    s = sub.add_parser("score", help="Score an exercise against exported logs")
    s.add_argument("--exercise", type=Path, required=True)
    s.add_argument("--logs", type=Path, nargs="+", required=True, help="ECS NDJSON and/or Windows event XML exports")
    s.add_argument("--format", choices=["auto", "ecs", "windows-xml"], default="auto")
    s.add_argument("--skew", type=float, default=None, help="Seconds of clock skew tolerated around each step")
    s.add_argument("--json", dest="json_out", type=Path)
    s.add_argument("--report", type=Path)
    s.add_argument("--navigator", type=Path, help="Write an ATT&CK Navigator layer here")
    s.add_argument("--min-coverage", type=float, help="Exit 2 if detection coverage is below this percentage")
    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (non-zero on validation or test failures)."""
    args = build_parser().parse_args(argv)
    load_dotenv(args.env_file)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    rules_paths = args.rules or [_env_path("COVERAGE_RULES_DIR", ROOT / "rules")]
    catalog_path = args.catalog or _env_path("COVERAGE_CATALOG", ROOT / "techniques" / "catalog.yml")
    try:
        rules = load_rules(rules_paths)
        by_id = {r.id: r for r in rules}
        catalog = load_catalog(catalog_path)

        if args.command == "lint":
            unknown = sorted({rid for t in catalog.values() for rid in t.expected_rules if rid not in by_id})
            if unknown:
                raise CatalogError(f"catalogue references unknown rule id(s): {', '.join(unknown)}")
            mismatched = [f"{t.id} -> {by_id[rid].title}" for t in catalog.values() for rid in t.expected_rules
                          if t.id not in by_id[rid].techniques]
            if mismatched:
                raise CatalogError("rule ATT&CK tags do not match catalogue: " + "; ".join(mismatched))
            if args.exercise:
                load_exercise(args.exercise, catalog)
            print(f"OK: {len(rules)} Sigma rules, {len(catalog)} techniques"
                  + (f", exercise {args.exercise}" if args.exercise else ""))
            return 0

        if args.command == "test-rules":
            cases_dir = args.cases or _env_path("COVERAGE_RULE_TESTS_DIR", ROOT / "rule-tests")
            total, failures, untested = run_rule_tests(cases_dir, by_id)
            for f in failures:
                print(f"FAIL {f}")
            for rid in untested:
                print(f"UNTESTED {rid} {by_id[rid].title}")
            print(f"{total - len(failures)}/{total} rule cases passed; {len(untested)} rule(s) without cases")
            return 1 if failures or (args.require_all and untested) else 0

        exercise = load_exercise(args.exercise, catalog)
        events = [e for path in args.logs for e in load_events(path, args.format)]
        skew = args.skew if args.skew is not None else float(os.environ.get("COVERAGE_SKEW_S", "5"))
        report = evaluate(exercise, catalog, rules, events, skew_s=skew)
        for path, doc in ((args.json_out, to_json(report, by_id)), (args.navigator, navigator_layer(report))):
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(to_markdown(report, by_id), encoding="utf-8")
        print(f"Detection coverage {report.detection_coverage}% | telemetry coverage {report.telemetry_coverage}% "
              f"| {len(report.techniques)} techniques, {len(events)} process events")
        for t in report.techniques:
            print(f"  {t.outcome:<14} {t.technique.id:<10} {t.technique.name}")
        if args.min_coverage is not None and report.detection_coverage < args.min_coverage:
            return 2
        return 0
    except (SigmaRuleError, CatalogError, LogFormatError, ValueError, OSError) as exc:
        logger.error("%s", exc)
        return 1
