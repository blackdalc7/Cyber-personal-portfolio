"""FIRST EPSS API client: probability that a CVE is exploited in the next 30 days."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .http import JsonFetcher

BATCH = 100   # the API accepts comma-separated CVE lists; keep URLs well under 2 KB


@dataclass(frozen=True)
class EpssScore:
    """FIRST EPSS score for one CVE: probability of exploitation in the next 30 days, and its percentile."""
    cve_id: str
    epss: float
    percentile: float
    date: str


class EpssClient:
    """Fetch EPSS scores in batches from the FIRST API."""
    def __init__(self, fetcher: JsonFetcher, url: str) -> None:
        self.fetcher = fetcher
        self.url = url

    def scores(self, cve_ids: Iterable[str]) -> dict[str, EpssScore]:
        """Return EPSS scores for ``cve_ids``, keyed by upper-case CVE id. Missing CVEs are omitted."""
        ids = sorted({c.upper() for c in cve_ids if c})
        out: dict[str, EpssScore] = {}
        for i in range(0, len(ids), BATCH):
            chunk = ids[i:i + BATCH]
            body = self.fetcher.get(self.url, {"cve": ",".join(chunk), "limit": len(chunk)})
            for row in body.get("data", []):
                try:
                    out[row["cve"].upper()] = EpssScore(row["cve"].upper(), float(row["epss"]),
                                                        float(row.get("percentile", 0.0)), row.get("date", ""))
                except (KeyError, TypeError, ValueError):
                    continue
        return out
