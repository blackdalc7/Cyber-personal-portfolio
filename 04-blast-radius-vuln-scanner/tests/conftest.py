"""Shared pytest fixtures built from the lab scan, inventory and local feeds."""

from pathlib import Path

import pytest

from vuln_scanner.analysis import Analyzer
from vuln_scanner.config import Settings
from vuln_scanner.feeds import EpssClient, KevCatalog, NvdClient
from vuln_scanner.feeds.local import DirectoryFetcher
from vuln_scanner.inventory import load_inventory
from vuln_scanner.nmap_parser import parse_nmap_xml

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@pytest.fixture
def settings() -> Settings:
    return Settings.from_env({})


@pytest.fixture
def lab_services():
    return parse_nmap_xml(EXAMPLES / "lab_scan.xml")


@pytest.fixture
def lab_inventory():
    return load_inventory(EXAMPLES / "inventory.yml")


@pytest.fixture
def local_fetcher(settings):
    return DirectoryFetcher(EXAMPLES / "feeds", settings.nvd_url, settings.epss_url, settings.kev_url)


@pytest.fixture
def analyzer(settings, local_fetcher):
    kev = KevCatalog.fetch(local_fetcher, settings.kev_url)
    return Analyzer(
        settings, NvdClient(local_fetcher, settings.nvd_url), EpssClient(local_fetcher, settings.epss_url), kev
    )


@pytest.fixture
def lab_result(analyzer, lab_services, lab_inventory):
    return analyzer.run(lab_services, lab_inventory)
