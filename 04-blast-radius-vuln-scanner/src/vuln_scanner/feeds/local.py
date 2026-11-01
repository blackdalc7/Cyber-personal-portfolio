"""Answer feed requests from a directory of JSON snapshots, for air-gapped runs, demos and tests.

Layout::

    <dir>/kev.json    the CISA KEV feed, unchanged
    <dir>/epss.json   {"data": [{"cve", "epss", "percentile", "date"}, ...]}, as the EPSS API returns
    <dir>/nvd.json    {"<cpe 2.3 match string>": {NVD 2.0 response}, ...}
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .http import FeedError


class DirectoryFetcher:
    """Serve NVD, EPSS and KEV responses from local JSON files instead of the network.

    Drop-in replacement for :class:`JsonFetcher`, used for demos, tests and
    air-gapped runs. ``network_calls`` stays at zero by design.
    """
    def __init__(self, directory: str | Path, nvd_url: str, epss_url: str, kev_url: str) -> None:
        self.directory = Path(directory)
        self.urls = {nvd_url: "nvd", epss_url: "epss", kev_url: "kev"}
        self._loaded: dict[str, Any] = {}
        self.network_calls = 0

    def _load(self, name: str) -> Any:
        """Load and memoise ``<directory>/<name>.json``."""
        if name not in self._loaded:
            path = self.directory / f"{name}.json"
            if not path.is_file():
                raise FeedError(f"local feed {path} not found")
            self._loaded[name] = json.loads(path.read_text(encoding="utf-8"))
        return self._loaded[name]

    def get(self, url: str, params: Mapping[str, Any] | None = None, headers: Mapping[str, str] | None = None) -> Any:
        """Answer a feed request from the local files, emulating each API's filtering and paging."""
        kind = self.urls.get(url)
        params = dict(params or {})
        if kind == "kev":
            return self._load("kev")
        if kind == "epss":
            wanted = set(str(params.get("cve", "")).upper().split(","))
            return {"data": [r for r in self._load("epss").get("data", []) if r["cve"].upper() in wanted]}
        if kind == "nvd":
            key = params.get("virtualMatchString") or params.get("keywordSearch") or ""
            body = self._load("nvd").get(key, {"totalResults": 0, "vulnerabilities": []})
            start = int(params.get("startIndex", 0))
            vulns = body.get("vulnerabilities", [])[start:start + int(params.get("resultsPerPage", 2000))]
            return {"totalResults": len(body.get("vulnerabilities", [])), "vulnerabilities": vulns}
        raise FeedError(f"no local feed for {url}")
