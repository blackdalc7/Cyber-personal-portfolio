"""ai-analyst: mcp | investigate | watch | eval | build-cmdb"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import replace
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError

from .cmdb import Cmdb, CmdbError, build_cmdb
from .config import ConfigError, Settings
from .engine import ProviderError, investigate, write_transcript
from .evals import markdown, run_suite
from .lake import LakeReader
from .providers import make_provider
from .tools import Toolbox, build_server
from .watch import Watcher

ROOT = Path(__file__).resolve().parents[2]


def _toolbox(settings: Settings) -> Toolbox:
    return Toolbox(LakeReader(settings.lake_dir), Cmdb.open(settings.cmdb_path, settings.cmdb_seed),
                   settings.max_rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ai-analyst", description="Read-only MCP analyst for the Watchfloor lake")
    ap.add_argument("--provider", choices=["offline", "anthropic", "ollama"], help="overrides ANALYST_PROVIDER")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mcp", help="serve the read-only tools over MCP")
    m.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    m.add_argument("--host", default="127.0.0.1")
    m.add_argument("--port", type=int, default=8765)
    i = sub.add_parser("investigate", help="investigate one incident and print or write the transcript")
    i.add_argument("--incident", required=True)
    i.add_argument("--write", action="store_true", help="also write it to ANALYST_OUT_DIR")
    w = sub.add_parser("watch", help="investigate new and changed incidents on a schedule")
    w.add_argument("--interval", type=float, default=60)
    w.add_argument("--once", action="store_true")
    e = sub.add_parser("eval", help="run the eval suite")
    e.add_argument("--cases", type=Path, default=ROOT / "evals")
    e.add_argument("--only")
    e.add_argument("--out", type=Path, help="write report JSON and Markdown here")
    e.add_argument("--min-pass-rate", type=float, default=1.0)
    b = sub.add_parser("build-cmdb", help="build the SQLite CMDB from a YAML seed")
    b.add_argument("--seed", type=Path, default=ROOT / "examples" / "cmdb_seed.yml")
    b.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                        stream=sys.stderr)
    for name in ("httpx", "httpx2", "mcp"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        settings = Settings.from_env()
        if args.provider:
            settings = replace(settings, provider=args.provider)
            settings.validate()
        if args.cmd == "build-cmdb":
            counts = build_cmdb(args.seed, args.out or settings.cmdb_path)
            print(json.dumps(counts))
            return 0
        if args.cmd == "eval":
            report = run_suite(args.cases, lambda: make_provider(settings), ROOT / "examples" / "cmdb_seed.yml",
                               args.only)
            text = markdown(report, settings.provider)
            print(text)
            if args.out:
                args.out.mkdir(parents=True, exist_ok=True)
                (args.out / f"eval-{settings.provider}.json").write_text(json.dumps(report, indent=2, default=str))
                (args.out / f"eval-{settings.provider}.md").write_text(text)
            return 0 if report["pass_rate"] >= args.min_pass_rate else 1
        box = _toolbox(settings)
        try:
            return _serve(args, settings, box)
        finally:
            box.lake.close()
            box.cmdb.close()
    except (ConfigError, CmdbError, ProviderError, ToolError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _serve(args: argparse.Namespace, settings: Settings, box: Toolbox) -> int:
    server = build_server(box)
    if args.cmd == "mcp":
        if args.transport == "stdio":
            server.run("stdio")
        else:
            server.run("streamable-http", host=args.host, port=args.port)
        return 0
    provider = make_provider(settings)
    if args.cmd == "investigate":
        doc = investigate(args.incident, box, server, provider, settings.max_tool_calls)
        if args.write:
            doc["incident_status"] = box.get_incident(args.incident)["incident"]["status"]
            print(write_transcript(doc, settings.out_dir), file=sys.stderr)
        print(json.dumps(doc, indent=2, ensure_ascii=False, default=str))
        return 0
    watcher = Watcher(box, server, provider, settings.out_dir, settings.max_tool_calls)
    if args.once:
        watcher.once()
    else:
        watcher.run(args.interval)
    return 0
