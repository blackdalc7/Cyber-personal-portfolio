"""Tests for end-to-end prioritisation on the lab network."""

from vuln_scanner.analysis import Analyzer
from vuln_scanner.feeds import EpssClient, FeedError, KevCatalog, NvdClient


def test_front_door_rce_ranks_first_and_cvss_ten_does_not(lab_result):
    order = [(f.asset_name, f.cve.cve_id) for f in lab_result.findings]
    assert order[0] == ("web01", "CVE-2021-42013")
    top_cvss = max(lab_result.findings, key=lambda f: f.cve.cvss)
    assert top_cvss.cve.cve_id == "CVE-2022-0543" and order.index(("cache01", "CVE-2022-0543")) > 2


def test_isolated_high_cvss_high_epss_host_is_deprioritised(lab_result):
    ftp = next(f for f in lab_result.findings if f.asset_name == "legacy-ftp")
    db = next(f for f in lab_result.findings if f.cve.cve_id == "CVE-2019-9193")
    assert ftp.cve.cvss > db.cve.cvss and ftp.epss > db.epss
    assert ftp.priority < db.priority  # unreachable, criticality 1, opens no doors


def test_kev_floor_applies(lab_result, analyzer):
    f = next(f for f in lab_result.findings if f.cve.cve_id == "CVE-2021-41773")
    assert f.kev and f.likelihood >= analyzer.settings.kev_likelihood_floor
    plain = next(f for f in lab_result.findings if f.cve.cve_id == "CVE-2018-1058")
    assert not plain.kev and plain.likelihood == plain.epss


def test_entry_points_and_findings_are_annotated(lab_result):
    assert lab_result.entry_points == ["10.10.1.10"]
    assert all(f.blast is not None for f in lab_result.findings)
    assert len(lab_result.findings) == 11 and not lab_result.errors


def test_feed_failures_degrade_instead_of_crashing(settings, lab_services, lab_inventory, local_fetcher):
    class Down:
        def get(self, *a, **k):
            raise FeedError("down")

    result = Analyzer(settings, NvdClient(Down(), "u"), EpssClient(Down(), "e"), KevCatalog({})).run(
        lab_services, lab_inventory
    )
    # every service with a versioned CPE is reported; the versionless RDP CPE is never queried
    assert result.findings == [] and len(result.errors) == len(lab_services) - 1

    kev = KevCatalog.fetch(local_fetcher, settings.kev_url)
    partial = Analyzer(settings, NvdClient(local_fetcher, settings.nvd_url), EpssClient(Down(), "e"), kev).run(
        lab_services, lab_inventory
    )
    assert any("EPSS unavailable" in e for e in partial.errors)
    assert partial.findings[0].kev  # KEV alone still drives the ranking
