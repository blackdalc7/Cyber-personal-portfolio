"""Command line: ``python -m vuln_scanner analyse scan.xml --inventory inventory.yml --sarif out.sarif``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .analysis import Analyzer
from .config import ConfigError, Settings
from .feeds import EpssClient, FeedError, HttpCache, JsonFetcher, KevCatalog, NvdClient
from .feeds.local import DirectoryFetcher
from .inventory import InventoryError, load_inventory
from .nmap_parser import parse_nmap_xml
from .render import export_graph_json, render_blast_radius
from .report import write_outputs
from .sarif import to_sarif, validate_sarif

logger = logging.getLogger("vuln_scanner")


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``analyse`` and ``snapshot`` subcommands."""
    p = argparse.ArgumentParser(prog="vuln-scanner", description="Blast-radius vulnerability prioritisation")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyse", aliases=["analyze"], help="Rank findings from one or more Nmap XML files")
    a.add_argument("scans", nargs="+", type=Path, help="Nmap XML (-oX) files")
    a.add_argument("--inventory", type=Path, help="Asset inventory and network policy YAML")
    a.add_argument("--sarif", type=Path, help="Write SARIF 2.1.0 here")
    a.add_argument("--sarif-base", type=Path, default=Path.cwd(),
                   help="Directory SARIF artifact URIs are relative to (default: current directory = repo root in CI)")
    a.add_argument("--json", dest="json_out", type=Path, help="Write findings JSON here")
    a.add_argument("--report", type=Path, help="Write a Markdown report here")
    a.add_argument("--graph", type=Path, help="Write the blast-radius image here (.png or .svg)")
    a.add_argument("--graph-json", type=Path, help="Write the annotated graph as node-link JSON here")
    a.add_argument("--focus", help="Draw the blast radius of this host IP, assumed compromised")
    a.add_argument("--feeds-dir", type=Path, help="Read NVD/EPSS/KEV snapshots from this directory (air-gapped)")
    a.add_argument("--offline", action="store_true", help="Use only the local cache, never the network")
    a.add_argument("--keyword-fallback", action="store_true",
                   help="Query NVD by banner text when Nmap found no CPE (lower precision)")
    a.add_argument("--top", type=int, default=15, help="Rows in the report's 'Fix first' table")
    a.add_argument("--fail-on", type=float, metavar="PRIORITY",
                   help="Exit 2 if any finding has priority >= this (CI gate)")
    a.add_argument("--env-file", default=None, help="Path to a .env file")
    a.add_argument("-v", "--verbose", action="store_true")

    sn = sub.add_parser("snapshot", help="Fetch live NVD/EPSS/KEV data for these scans into a --feeds-dir directory")
    sn.add_argument("scans", nargs="+", type=Path)
    sn.add_argument("--out", type=Path, required=True, help="Directory to write nvd.json, epss.json, kev.json")
    sn.add_argument("--keyword-fallback", action="store_true")
    sn.add_argument("--env-file", default=None)
    sn.add_argument("-v", "--verbose", action="store_true")
    return p


def run_snapshot(args: argparse.Namespace) -> int:
    """Record the live feed responses needed for these scans, for later air-gapped or reproducible runs."""
    settings = Settings.from_env(dotenv_path=args.env_file)
    services = [svc for scan in args.scans for svc in parse_nmap_xml(scan)]
    cache = HttpCache(settings.cache_path, settings.cache_ttl_s)
    try:
        nvd_fetcher = JsonFetcher(cache, timeout_s=settings.http_timeout_s, min_interval_s=settings.nvd_delay_s)
        other = JsonFetcher(cache, timeout_s=settings.http_timeout_s, min_interval_s=0.2)
        recorded: dict[str, dict] = {}
        original_get = nvd_fetcher.get

        def recording_get(url, params=None, headers=None):
            body = original_get(url, params, headers)
            key = (params or {}).get("virtualMatchString") or (params or {}).get("keywordSearch") or ""
            entry = recorded.setdefault(key, {"totalResults": 0, "vulnerabilities": []})
            entry["vulnerabilities"].extend(body.get("vulnerabilities", []))
            entry["totalResults"] = len(entry["vulnerabilities"])
            return body

        nvd_fetcher.get = recording_get  # type: ignore[method-assign]
        nvd = NvdClient(nvd_fetcher, settings.nvd_url, settings.nvd_api_key, keyword_fallback=args.keyword_fallback)
        ids: set[str] = set()
        for svc in services:
            ids |= {c.cve_id for c in nvd.cves_for(svc)}
        epss = EpssClient(other, settings.epss_url).scores(ids)
        kev_body = other.get(settings.kev_url)
    finally:
        cache.close()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "nvd.json").write_text(json.dumps(recorded, indent=1), encoding="utf-8")
    (args.out / "epss.json").write_text(json.dumps({"data": [
        {"cve": e.cve_id, "epss": e.epss, "percentile": e.percentile, "date": e.date} for e in epss.values()]},
        indent=1), encoding="utf-8")
    (args.out / "kev.json").write_text(json.dumps(kev_body), encoding="utf-8")
    print(f"Snapshot of {len(ids)} CVEs for {len(services)} services written to {args.out}")
    return 0


def run_analyse(args: argparse.Namespace) -> int:
    """Execute ``analyse``: parse scans, score findings and write the requested outputs.

    Returns 0, or 2 when ``--fail-on`` is set and a finding meets that priority.
    """
    settings = Settings.from_env(dotenv_path=args.env_file)
    if args.offline:
        settings = Settings(**{**settings.__dict__, "offline": True})
    services = []
    for scan in args.scans:
        services.extend(parse_nmap_xml(scan))
    inventory = load_inventory(args.inventory)

    cache = None
    if args.feeds_dir:
        fetcher = DirectoryFetcher(args.feeds_dir, settings.nvd_url, settings.epss_url, settings.kev_url)
        nvd_fetcher = epss_fetcher = fetcher
    else:
        cache = HttpCache(settings.cache_path, settings.cache_ttl_s)
        nvd_fetcher = JsonFetcher(cache, offline=settings.offline, timeout_s=settings.http_timeout_s,
                                  min_interval_s=settings.nvd_delay_s)
        epss_fetcher = JsonFetcher(cache, offline=settings.offline, timeout_s=settings.http_timeout_s,
                                   min_interval_s=0.2)
    try:
        try:
            kev = KevCatalog.fetch(epss_fetcher, settings.kev_url)
        except FeedError as exc:
            logger.warning("CISA KEV unavailable: %s", exc)
            kev = KevCatalog({})
        analyzer = Analyzer(settings, NvdClient(nvd_fetcher, settings.nvd_url, settings.nvd_api_key,
                                                keyword_fallback=args.keyword_fallback),
                            EpssClient(epss_fetcher, settings.epss_url), kev)
        result = analyzer.run(services, inventory)
    finally:
        if cache is not None:
            cache.close()

    if args.sarif:
        doc = to_sarif(result, base=args.sarif_base)
        problems = validate_sarif(doc)
        if problems:
            raise RuntimeError("generated SARIF failed validation: " + "; ".join(problems))
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    graph_rel = None
    if args.graph:
        render_blast_radius(result, args.graph, focus=args.focus)
        if args.report:
            graph_rel = Path(os.path.relpath(args.graph.resolve(), args.report.parent.resolve())).as_posix()
    if args.graph_json:
        export_graph_json(result, args.graph_json)
    write_outputs(result, json_path=args.json_out, md_path=args.report, top=args.top, graph_rel=graph_rel)

    for err in result.errors:
        logger.warning(err)
    print(f"{len(result.findings)} findings across {len({s.host for s in services})} hosts; "
          f"{len(result.entry_points)} entry point(s); {len(result.paths)} attack path(s) to crown jewels.")
    for f in result.findings[:5]:
        print(f"  {f.priority:6.1f}  {f.cve.cve_id:<16} {f.asset_name:<12} {f.service.key:<22} "
              f"EPSS {f.epss:.3f}{'  KEV' if f.kev else ''}  blast {len(f.blast.targets) if f.blast else 0}")
    if args.fail_on is not None and any(f.priority >= args.fail_on for f in result.findings):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (1 on configuration, feed or I/O errors)."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    try:
        return run_snapshot(args) if args.command == "snapshot" else run_analyse(args)
    except (ConfigError, InventoryError, FeedError, ValueError, OSError) as exc:
        logger.error("%s", exc)
        return 1
