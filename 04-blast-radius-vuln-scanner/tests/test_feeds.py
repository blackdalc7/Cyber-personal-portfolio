"""Tests for the NVD, EPSS and KEV clients and the HTTP cache."""

import json

import pytest
import requests
import responses

from vuln_scanner.feeds import EpssClient, FeedError, HttpCache, JsonFetcher, KevCatalog, NvdClient
from vuln_scanner.feeds.local import DirectoryFetcher
from vuln_scanner.feeds.nvd import parse_cve
from vuln_scanner.nmap_parser import Service

URL = "https://feed.example/api"


class FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s

    def clock(self):
        return self.now


@pytest.fixture
def make_cache(tmp_path):
    made = []

    def factory(ttl_s, clock):
        c = HttpCache(tmp_path / f"c{len(made)}.sqlite", ttl_s=ttl_s, clock=clock)
        made.append(c)
        return c

    yield factory
    for c in made:
        c.close()


@pytest.fixture
def cache(tmp_path):
    c = HttpCache(tmp_path / "c.sqlite", ttl_s=3600)
    yield c
    c.close()


def fetcher(cache, **kw):
    t = FakeTime()
    return JsonFetcher(cache, sleep=t.sleep, clock=t.clock, **kw), t


@responses.activate
def test_caches_successful_responses(cache):
    responses.get(URL, json={"ok": 1})
    f, _ = fetcher(cache)
    assert f.get(URL, {"a": 1}) == {"ok": 1}
    assert f.get(URL, {"a": 1}) == {"ok": 1}
    assert len(responses.calls) == 1 and f.network_calls == 1


@responses.activate
def test_cache_expires_after_ttl(make_cache):
    now = [0.0]
    cache = make_cache(10, lambda: now[0])
    responses.get(URL, json={"v": 1})
    responses.get(URL, json={"v": 2})
    f, _ = fetcher(cache)
    assert f.get(URL)["v"] == 1
    now[0] = 11
    assert f.get(URL)["v"] == 2


@responses.activate
def test_retries_rate_limit_then_succeeds_honouring_retry_after(cache):
    responses.get(URL, status=403)
    responses.get(URL, status=429, headers={"Retry-After": "7"})
    responses.get(URL, json={"ok": True})
    f, t = fetcher(cache)
    assert f.get(URL) == {"ok": True}
    assert 7.0 in t.sleeps
    assert len(responses.calls) == 3


@responses.activate
def test_non_retryable_status_raises_immediately(cache):
    responses.get(URL, status=404)
    f, _ = fetcher(cache)
    with pytest.raises(FeedError, match="HTTP 404"):
        f.get(URL)
    assert len(responses.calls) == 1


@responses.activate
def test_invalid_json_raises(cache):
    responses.get(URL, body="<html>")
    f, _ = fetcher(cache)
    with pytest.raises(FeedError, match="invalid JSON"):
        f.get(URL)


@responses.activate
def test_gives_up_after_retries(cache):
    responses.get(URL, body=requests.ConnectionError("boom"))
    f, _ = fetcher(cache, retries=2)
    with pytest.raises(FeedError, match="3 attempts"):
        f.get(URL)


@responses.activate
def test_falls_back_to_stale_cache_when_feed_is_down(make_cache):
    now = [0.0]
    cache = make_cache(10, lambda: now[0])
    cache.put(HttpCache.key(URL, None), {"stale": True})
    now[0] = 100
    responses.get(URL, status=503)
    f, _ = fetcher(cache, retries=1)
    assert f.get(URL) == {"stale": True}


def test_offline_uses_stale_cache_and_never_calls_network(make_cache):
    now = [0.0]
    cache = make_cache(10, lambda: now[0])
    cache.put(HttpCache.key(URL, {"q": 1}), {"x": 1})
    now[0] = 1e6
    f, _ = fetcher(cache, offline=True)
    assert f.get(URL, {"q": 1}) == {"x": 1}
    with pytest.raises(FeedError, match="offline"):
        f.get(URL, {"q": 2})
    assert f.network_calls == 0


@responses.activate
def test_spaces_requests_for_rate_limits(cache):
    responses.get(URL, json={})
    f, t = fetcher(cache, min_interval_s=6.5)
    f.get(URL, {"p": 1})
    f.get(URL, {"p": 2})
    assert t.sleeps == [pytest.approx(6.5)]


def nvd_item(cid, score=7.5, status="Analyzed", metric="cvssMetricV31"):
    return {
        "cve": {
            "id": cid,
            "vulnStatus": status,
            "published": "2021-01-01",
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": f"desc {cid}"}],
            "metrics": {
                metric: [
                    {"type": "Secondary", "cvssData": {"baseScore": 1.0, "vectorString": "s"}},
                    {"type": "Primary", "cvssData": {"baseScore": score, "vectorString": "v"}},
                ]
            },
            "weaknesses": [{"description": [{"value": "CWE-22"}, {"value": "NVD-CWE-Other"}]}],
            "references": [{"url": "https://ex/1"}],
        }
    }


def test_parse_cve_prefers_primary_and_newest_cvss():
    c = parse_cve(nvd_item("CVE-1", 9.1))
    assert (c.cvss, c.cvss_vector, c.cvss_version, c.cwes, c.description) == (
        9.1,
        "v",
        "3.1",
        ("CWE-22",),
        "desc CVE-1",
    )
    assert parse_cve(nvd_item("CVE-2", 5.0, metric="cvssMetricV2")).cvss_version == "2.0"
    unscored = parse_cve({"cve": {"id": "CVE-3", "metrics": {}}})
    assert unscored.cvss is None


@responses.activate
def test_nvd_paginates_filters_rejected_and_sends_api_key(cache):
    svc = Service("10.0.0.1", 80, "tcp", "http", "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49")
    responses.get(
        "https://nvd.example/cves",
        json={"totalResults": 3, "vulnerabilities": [nvd_item("CVE-A"), nvd_item("CVE-R", status="Rejected")]},
    )
    responses.get("https://nvd.example/cves", json={"totalResults": 3, "vulnerabilities": [nvd_item("CVE-B")]})
    f, _ = fetcher(cache)
    cves = NvdClient(f, "https://nvd.example/cves", api_key="k").cves_for(svc)
    assert [c.cve_id for c in cves] == ["CVE-A", "CVE-B"]
    assert responses.calls[0].request.headers["apiKey"] == "k"
    assert "virtualMatchString=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.49" in responses.calls[0].request.url
    assert "startIndex=2" in responses.calls[1].request.url


def test_nvd_skips_versionless_cpe_and_uses_keyword_only_when_enabled(cache):
    calls = []

    class Recorder:
        def get(self, url, params=None, headers=None):
            calls.append(params)
            return {"totalResults": 1, "vulnerabilities": [nvd_item("CVE-K")]}

    rdp = Service(
        "10.0.0.1", 3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", "", "cpe:/o:microsoft:windows"
    )
    assert NvdClient(Recorder(), "u").cves_for(rdp) == []
    nocpe = Service("10.0.0.1", 21, "tcp", "ftp", "ProFTPD", "1.3.5")
    assert NvdClient(Recorder(), "u").cves_for(nocpe) == []
    found = NvdClient(Recorder(), "u", keyword_fallback=True).cves_for(nocpe)
    assert found[0].match == "keyword" and calls[-1]["keywordSearch"] == "ProFTPD 1.3.5"


def test_epss_batches_and_ignores_bad_rows():
    seen = []

    class Recorder:
        def get(self, url, params=None, headers=None):
            seen.append(params["cve"].split(","))
            return {
                "data": [{"cve": c.lower(), "epss": "0.5", "percentile": "0.9"} for c in params["cve"].split(",")]
                + [{"cve": "CVE-X", "epss": "nan?"}]
            }

    ids = [f"CVE-2024-{i:04d}" for i in range(250)]
    scores = EpssClient(Recorder(), "u").scores([*ids, "", ids[0]])
    assert [len(b) for b in seen] == [100, 100, 50]
    assert len(scores) == 250 and scores[ids[3]].epss == 0.5


def test_kev_catalogue():
    kev = KevCatalog.from_feed(
        {
            "catalogVersion": "1",
            "vulnerabilities": [
                {"cveID": "cve-2017-7494", "knownRansomwareCampaignUse": "Known", "dateAdded": "2023-03-30"},
                {"cveID": ""},
            ],
        }
    )
    assert "CVE-2017-7494" in kev and kev.get("cve-2017-7494").ransomware
    assert kev.get("CVE-1") is None and len(kev.entries) == 1


def test_directory_fetcher(tmp_path, settings):
    (tmp_path / "kev.json").write_text(json.dumps({"vulnerabilities": []}))
    (tmp_path / "epss.json").write_text(
        json.dumps({"data": [{"cve": "CVE-1", "epss": "0.1"}, {"cve": "CVE-2", "epss": "0.2"}]})
    )
    (tmp_path / "nvd.json").write_text(json.dumps({"cpe": {"vulnerabilities": [nvd_item("CVE-1"), nvd_item("CVE-2")]}}))
    d = DirectoryFetcher(tmp_path, settings.nvd_url, settings.epss_url, settings.kev_url)
    assert d.get(settings.epss_url, {"cve": "CVE-2"})["data"][0]["cve"] == "CVE-2"
    page = d.get(settings.nvd_url, {"virtualMatchString": "cpe", "startIndex": 1, "resultsPerPage": 5})
    assert page["totalResults"] == 2 and len(page["vulnerabilities"]) == 1
    assert d.get(settings.nvd_url, {"virtualMatchString": "other"})["vulnerabilities"] == []
    with pytest.raises(FeedError):
        d.get("https://elsewhere")
    with pytest.raises(FeedError, match="not found"):
        DirectoryFetcher(tmp_path / "missing", "n", "e", "k").get("k")
