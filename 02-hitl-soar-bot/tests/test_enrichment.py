"""Tests for threat-intel enrichment and risk scoring."""

import requests
import responses

from soar_bot.enrichment import ABUSEIPDB_URL, Enricher, risk_score


def test_internal_and_invalid_ips_never_leave():
    e = Enricher("key")
    assert e.enrich("10.1.2.3")["scope"] == "internal"
    assert e.enrich("not-ip") == {"error": "invalid ip"}
    assert e.enrich(None) == {}


def test_no_key():
    assert Enricher("").enrich("8.8.8.8")["abuseipdb"] is None


@responses.activate
def test_abuseipdb_lookup_and_cache():
    responses.get(ABUSEIPDB_URL, json={"data": {"abuseConfidenceScore": 100, "totalReports": 900,
                                                "countryCode": "DE", "isp": "x", "isTor": True}})
    e = Enricher("key")
    r = e.enrich("185.220.101.1")
    assert r["abuseipdb"]["abuse_confidence"] == 100 and r["abuseipdb"]["is_tor"] is True
    e.enrich("185.220.101.1")
    assert len(responses.calls) == 1  # cached
    assert responses.calls[0].request.headers["Key"] == "key"
    assert risk_score("high", r) == 85
    assert risk_score("critical", r) == 100


@responses.activate
def test_abuseipdb_failures_degrade():
    responses.get(ABUSEIPDB_URL, status=429)
    assert "429" in Enricher("k").enrich("1.1.1.1")["error"]
    responses.replace(responses.GET, ABUSEIPDB_URL, body="nope")
    assert "malformed" in Enricher("k").enrich("1.1.1.1")["error"]
    responses.replace(responses.GET, ABUSEIPDB_URL, body=requests.ConnectionError("down"))
    assert "network" in Enricher("k").enrich("1.1.1.1")["error"]


def test_risk_score_bounds():
    assert risk_score("low", {}) == 10
    assert risk_score("unknown", {}) == 35
