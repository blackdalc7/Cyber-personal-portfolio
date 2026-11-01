"""NIST NVD 2.0 CVE API client (CPE-based lookup, paginated)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..nmap_parser import Service, cpe22_to_23
from .http import JsonFetcher

logger = logging.getLogger("vuln_scanner.nvd")
PAGE_SIZE = 2000   # NVD maximum


@dataclass(frozen=True)
class CveRecord:
    """The fields of an NVD CVE record that scoring and reporting need.

    ``match`` is ``cpe`` for an exact product and version match, or ``keyword``
    for a lower-confidence match on banner text.
    """
    cve_id: str
    cvss: float | None
    cvss_vector: str
    cvss_version: str
    description: str
    published: str
    cwes: tuple[str, ...] = ()
    references: tuple[str, ...] = field(default=(), repr=False)
    match: str = "cpe"   # "cpe" (exact product/version) or "keyword" (banner text, lower confidence)


def _best_metric(metrics: dict[str, Any]) -> tuple[float | None, str, str]:
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        score = data.get("baseScore")
        return (float(score) if score is not None else None), data.get("vectorString", ""), version
    return None, "", ""


def parse_cve(item: dict[str, Any], match: str = "cpe") -> CveRecord:
    """Convert one NVD API 2.0 vulnerability item into a :class:`CveRecord`."""
    cve = item.get("cve", item)
    score, vector, version = _best_metric(cve.get("metrics", {}))
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = tuple(sorted({d.get("value", "") for w in cve.get("weaknesses", []) for d in w.get("description", [])
                         if d.get("value", "").startswith("CWE-")}))
    refs = tuple(r.get("url", "") for r in cve.get("references", []) if r.get("url"))
    return CveRecord(cve_id=cve["id"], cvss=score, cvss_vector=vector, cvss_version=version, description=desc[:2000],
                     published=cve.get("published", ""), cwes=cwes, references=refs[:20], match=match)


class NvdClient:
    """Query the NVD CVE API 2.0 by CPE, with an optional keyword fallback."""
    def __init__(self, fetcher: JsonFetcher, url: str, api_key: str = "", keyword_fallback: bool = False) -> None:
        self.fetcher = fetcher
        self.url = url
        self.api_key = api_key
        self.keyword_fallback = keyword_fallback

    def _query(self, params: dict[str, Any], match: str) -> list[CveRecord]:
        """Run one NVD query, following ``startIndex`` paging until every result is read."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        out: list[CveRecord] = []
        start = 0
        while True:
            body = self.fetcher.get(self.url, {**params, "resultsPerPage": PAGE_SIZE, "startIndex": start}, headers)
            vulns = body.get("vulnerabilities", [])
            out.extend(parse_cve(v, match) for v in vulns if v.get("cve", {}).get("vulnStatus") != "Rejected")
            start += len(vulns)
            if not vulns or start >= int(body.get("totalResults", 0)):
                return out

    def cves_for(self, service: Service) -> list[CveRecord]:
        """Return the CVEs that apply to ``service``.

        Uses the service's CPE when it carries a version. Falls back to a keyword
        search on product and version only when ``keyword_fallback`` is enabled.
        """
        if service.cpe:
            try:
                cpe = cpe22_to_23(service.cpe)
            except ValueError:
                cpe = ""
            # A CPE without a version would match every release ever shipped.
            if cpe and cpe.split(":")[5] not in ("*", "-", ""):
                return self._query({"virtualMatchString": cpe}, "cpe")
        if self.keyword_fallback and service.product and service.version:
            return self._query({"keywordSearch": f"{service.product} {service.version}"}, "keyword")
        return []
