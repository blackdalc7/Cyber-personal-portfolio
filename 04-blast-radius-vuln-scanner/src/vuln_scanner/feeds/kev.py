"""CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .http import JsonFetcher


@dataclass(frozen=True)
class KevEntry:
    """One entry of the CISA Known Exploited Vulnerabilities catalogue."""
    cve_id: str
    date_added: str
    due_date: str
    ransomware: bool
    required_action: str


class KevCatalog:
    """The CISA KEV catalogue, indexed by CVE id for constant-time lookups."""
    def __init__(self, entries: dict[str, KevEntry], version: str = "") -> None:
        self.entries = entries
        self.version = version

    @classmethod
    def from_feed(cls, body: dict[str, Any]) -> KevCatalog:
        """Parse the KEV JSON feed body into a catalogue."""
        entries = {}
        for v in body.get("vulnerabilities", []):
            cve = str(v.get("cveID", "")).upper()
            if cve:
                entries[cve] = KevEntry(cve, v.get("dateAdded", ""), v.get("dueDate", ""),
                                        str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                                        v.get("requiredAction", ""))
        return cls(entries, body.get("catalogVersion", ""))

    @classmethod
    def fetch(cls, fetcher: JsonFetcher, url: str) -> KevCatalog:
        """Download (or load from cache) the KEV feed and parse it."""
        return cls.from_feed(fetcher.get(url))

    def get(self, cve_id: str) -> KevEntry | None:
        """Return the KEV entry for ``cve_id``, or ``None`` if it is not known to be exploited."""
        return self.entries.get(cve_id.upper())

    def __contains__(self, cve_id: str) -> bool:
        return cve_id.upper() in self.entries
