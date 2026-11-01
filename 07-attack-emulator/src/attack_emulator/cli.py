"""``attack-emulator validate | run | report``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

import httpx

from . import __version__
from .campaign import Campaign, CampaignError, load_campaign
from .config import ConfigError, Settings
from .executors import DryRunExecutor, Executor, KubectlExecutor, ReplayExecutor, SshExecutor, WinRmExecutor
from .poller import HubClient
from .report import markdown, run_doc, write_outputs
from .runner import new_run_id, run_campaign
from .safety import SafetyError, check_campaign

log = logging.getLogger("attack_emulator")


def build_executors(campaign: Campaign, settings: Settings, *, dry_run: bool, run_id: str,
                    fixtures: Path | None) -> dict[str, Executor]:
    """One executor per executor kind the campaign uses. ``--dry-run`` swaps every one for the dry-run printer."""
    kinds = {t.executor for t in campaign.targets.values()}
    if dry_run:
        dry = DryRunExecutor()
        return dict.fromkeys(kinds, dry)
    out: dict[str, Executor] = {}
    for kind in kinds:
        if kind == "dry-run":
            out[kind] = DryRunExecutor()
        elif kind == "replay":
            if fixtures is None:
                raise ConfigError("replay targets need --fixtures (a directory of <technique>.ndjson files)")
            out[kind] = ReplayExecutor(settings.hub_url, settings.ingest_token, fixtures, run_id)
        elif kind == "kubectl":
            out[kind] = KubectlExecutor()
        elif kind == "winrm":
            out[kind] = WinRmExecutor(settings.winrm_user, settings.winrm_password, settings.winrm_transport)
        elif kind == "ssh":
            out[kind] = SshExecutor(settings.ssh_user, settings.ssh_key, settings.ssh_trust_lab_hostkeys)
    return out


def cmd_validate(args: argparse.Namespace) -> int:
    for path in args.campaigns:
        c = load_campaign(path)
        kinds = sorted({t.executor for t in c.targets.values()})
        print(f"ok  {path}: {c.name!r}, {len(c.tests)} tests on {len(c.targets)} targets ({', '.join(kinds)})")
    return 0


def cmd_run(args: argparse.Namespace, settings: Settings) -> int:
    """Run a campaign (after the lab safety checks unless ``--dry-run``), score it and write the outputs."""
    campaign = load_campaign(args.campaign)
    if not args.dry_run:
        for note in check_campaign(campaign, settings, confirm=args.confirm_lab):
            log.info("safety: %s", note)
    run_id = new_run_id()
    executors = build_executors(campaign, settings, dry_run=args.dry_run, run_id=run_id, fixtures=args.fixtures)
    hub = None if args.dry_run else HubClient(settings.hub_url, settings.hub_token)
    try:
        if hub is not None:
            hub.health()  # fail fast: polling a hub that is down would score every technique as an error
        only = {t.strip().upper() for t in args.only.split(",")} if args.only else None
        result = run_campaign(campaign, settings, executors, hub, run_id=run_id, only=only)
    finally:
        for ex in {id(e): e for e in executors.values()}.values():
            ex.close()
        if hub is not None:
            hub.close()
    if args.dry_run:
        for ex in executors.values():
            if isinstance(ex, DryRunExecutor):
                print("\n".join(ex.commands))
                break
    doc = run_doc(result)
    paths = write_outputs(doc, args.out or settings.out_dir)
    s = doc["summary"]
    print(f"{run_id}: detection coverage {s['detection_coverage']}% ({s['detected']} detected, {s['prevented']} "
          f"prevented, {s['telemetry_only']} telemetry only, {s['missed']} missed, {s['error']} errors, "
          f"{s['skipped']} skipped)")
    for kind, p in paths.items():
        print(f"  {kind:<9} {p}")
    return 0 if not s["error"] else 1


def cmd_report(args: argparse.Namespace) -> int:
    doc = json.loads(Path(args.run).read_text(encoding="utf-8"))
    if doc.get("kind") != "emulation-run":
        raise CampaignError(f"{args.run} is not an emulation-run document")
    sys.stdout.write(markdown(doc))
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="attack-emulator", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check campaign files without touching anything")
    v.add_argument("campaigns", nargs="+", type=Path)
    r = sub.add_parser("run", help="run a campaign and score it against the Watchfloor hub")
    r.add_argument("campaign", type=Path)
    r.add_argument("--confirm-lab", action="store_true",
                   help="required for winrm/ssh/kubectl targets: you checked they are disposable lab machines")
    r.add_argument("--dry-run", action="store_true", help="print the commands, execute nothing, contact nothing")
    r.add_argument("--only", help="comma-separated technique ids to run (T1059 also matches T1059.001)")
    r.add_argument("--fixtures", type=Path, help="replay fixture directory (replay targets only)")
    r.add_argument("--out", type=Path, help="output directory (default EMU_OUT_DIR or ./results)")
    rep = sub.add_parser("report", help="print a run document as Markdown")
    rep.add_argument("run", type=Path)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")
    try:
        if args.cmd == "validate":
            return cmd_validate(args)
        if args.cmd == "report":
            return cmd_report(args)
        return cmd_run(args, Settings.from_env())
    except httpx.HTTPError as exc:
        print(f"attack-emulator: hub unreachable ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 2
    except (CampaignError, ConfigError, SafetyError, ValueError, OSError) as exc:
        print(f"attack-emulator: {exc}", file=sys.stderr)
        return 2
