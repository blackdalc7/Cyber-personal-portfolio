"""``evidence-timeline serve | collect | verify``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import ConfigError, Settings
from .jobs import CollectRequest, collect
from .package import verify_package
from .velociraptor import VelociraptorError


def cmd_serve(settings: Settings, args: argparse.Namespace) -> int:
    if len(settings.shared_secret) < 32:
        raise ConfigError("EVIDENCE_SHARED_SECRET must be set (>= 32 chars): /collect only accepts signed requests")
    import uvicorn

    from .app import create_app
    uvicorn.run(create_app(settings), host=settings.listen_host, port=settings.listen_port, log_level="info",
                server_header=False)
    return 0


def cmd_collect(settings: Settings, args: argparse.Namespace) -> int:
    path, n = collect(CollectRequest(incident_id=args.incident, host=args.host, around_ms=args.around_ms,
                                     requested_by="cli", reason=args.reason), settings)
    print(f"{path}: {n} timeline rows")
    return 0


def cmd_verify(settings: Settings, args: argparse.Namespace) -> int:
    bad = 0
    for p in args.packages:
        problems = verify_package(Path(p))
        bad += bool(problems)
        print(json.dumps({"package": str(p), "intact": not problems, "problems": problems}))
    return 1 if bad else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evidence-timeline", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the signed HTTP API n8n calls")
    c = sub.add_parser("collect", help="collect once from the command line")
    c.add_argument("--incident", required=True)
    c.add_argument("--host", required=True)
    c.add_argument("--around-ms", type=int, help="incident time (epoch ms) to centre the telemetry window on")
    c.add_argument("--reason")
    v = sub.add_parser("verify", help="re-hash packages against their manifests")
    v.add_argument("packages", nargs="+")
    return p


COMMANDS = {"serve": cmd_serve, "collect": cmd_collect, "verify": cmd_verify}


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        return COMMANDS[args.cmd](Settings.from_env(), args)
    except (ConfigError, VelociraptorError, OSError, ValueError) as exc:
        print(f"evidence-timeline: {exc}", file=sys.stderr)
        return 2
