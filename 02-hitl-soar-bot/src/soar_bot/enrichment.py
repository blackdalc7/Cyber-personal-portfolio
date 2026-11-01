"""Lightweight threat-intel enrichment and risk scoring.

Only globally routable IPs are sent to third parties (data minimisation: an
internal 10.x address reveals network layout and has no public reputation).
Every failure degrades to "no intel"; enrichment can never block the
approval request from reaching the analyst.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Any

import requests

logger = logging.getLogger("soar_bot.enrichment")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SEVERITY_BASE = {"low": 10, "medium": 35, "high": 60, "critical": 80}


class Enricher:
    """Look up threat intel for an indicator IP, with an in-memory TTL cache.

    Private and other non-public addresses are never sent to a third party.
    Without an AbuseIPDB key, lookups return an empty result.
    """
    def __init__(self, abuseipdb_key: str = "", timeout_s: float = 10, cache_ttl_s: float = 3600,
                 session: requests.Session | None = None) -> None:
        self.key = abuseipdb_key
        self.timeout = timeout_s
        self.ttl = cache_ttl_s
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "hitl-soar-bot/1.0")
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def enrich(self, ip: str | None) -> dict[str, Any]:
        """Return intel for ``ip``: AbuseIPDB data, an ``internal`` marker, or an ``error`` key."""
        if not ip:
            return {}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": "invalid ip"}
        if not addr.is_global:
            return {"ip": ip, "scope": "internal", "note": "non-public IP: not sent to third parties"}
        with self._lock:
            hit = self._cache.get(ip)
            if hit and time.monotonic() - hit[0] < self.ttl:
                return hit[1]
        result = self._abuseipdb(ip)
        if "error" not in result:
            with self._lock:
                self._cache[ip] = (time.monotonic(), result)
        return result

    def _abuseipdb(self, ip: str) -> dict[str, Any]:
        if not self.key:
            return {"ip": ip, "scope": "public", "abuseipdb": None, "note": "ABUSEIPDB_API_KEY not set"}
        try:
            resp = self.session.get(ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": 90},
                                    headers={"Key": self.key, "Accept": "application/json"}, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, type(exc).__name__)
            return {"ip": ip, "error": f"network: {type(exc).__name__}"}
        if resp.status_code != 200:
            return {"ip": ip, "error": f"AbuseIPDB HTTP {resp.status_code}"}
        try:
            d = resp.json()["data"]
        except (ValueError, KeyError):
            return {"ip": ip, "error": "AbuseIPDB returned malformed JSON"}
        return {
            "ip": ip, "scope": "public",
            "abuseipdb": {
                "abuse_confidence": int(d.get("abuseConfidenceScore", 0)),
                "total_reports": int(d.get("totalReports", 0)),
                "country": d.get("countryCode"), "isp": d.get("isp"), "is_tor": bool(d.get("isTor")),
                "usage_type": d.get("usageType"),
            },
            "reference": f"https://www.abuseipdb.com/check/{ip}",
        }


def risk_score(severity: str, enrichment: dict[str, Any]) -> int:
    """0-100: alert severity as the base, raised by external reputation."""
    score = SEVERITY_BASE.get(severity, 35)
    abuse = (enrichment or {}).get("abuseipdb") or {}
    score += int(abuse.get("abuse_confidence", 0) * 0.2)
    if abuse.get("is_tor"):
        score += 5
    return max(0, min(100, score))
