"""Shared HTTP plumbing for the threat-intel feeds: SQLite response cache, pacing, retries.

Every feed is public, rate limited and slow-changing (EPSS and KEV publish daily), so a
local cache with a TTL keeps repeat scans fast, polite to the providers, and usable
offline from the last good copy.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("vuln_scanner.feeds")
RETRY_STATUSES = {403, 429, 500, 502, 503, 504}   # NVD answers 403 when rate limited


class FeedError(RuntimeError):
    """Raised when a feed cannot be fetched and no cached copy is available."""


class HttpCache:
    """SQLite cache of JSON responses, keyed by URL and parameters, with a TTL.

    Stale entries are kept so offline runs can still use the last good response.
    """
    def __init__(self, path: Path | str, ttl_s: int, clock: Callable[[], float] = time.time) -> None:
        self.ttl_s = ttl_s
        self.clock = clock
        path = Path(path)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("CREATE TABLE IF NOT EXISTS responses (key TEXT PRIMARY KEY, fetched_at REAL, body TEXT)")
            self._db.commit()

    @staticmethod
    def key(url: str, params: Mapping[str, Any] | None) -> str:
        """Stable cache key: SHA-256 of the URL plus sorted query parameters."""
        canonical = url + "?" + json.dumps(sorted((params or {}).items()), separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, key: str, allow_stale: bool = False) -> Any | None:
        """Return the cached body for ``key``, or ``None`` if missing or (unless ``allow_stale``) expired."""
        with self._lock:
            row = self._db.execute("SELECT fetched_at, body FROM responses WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        if not allow_stale and self.clock() - row[0] > self.ttl_s:
            return None
        return json.loads(row[1])

    def put(self, key: str, body: Any) -> None:
        """Store ``body`` under ``key`` with the current time."""
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO responses VALUES (?, ?, ?)", (key, self.clock(), json.dumps(body)))
            self._db.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._db.close()


class JsonFetcher:
    """GET JSON with cache-first lookup, minimum spacing between calls, and bounded retries."""

    def __init__(self, cache: HttpCache, *, offline: bool = False, timeout_s: float = 30.0, min_interval_s: float = 0.0,
                 retries: int = 4, session: requests.Session | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self.cache = cache
        self.offline = offline
        self.timeout_s = timeout_s
        self.min_interval_s = min_interval_s
        self.retries = retries
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", "blast-radius-vuln-scanner/1.0 (+defensive use)")
        self.sleep = sleep
        self.clock = clock
        self._last_call = float("-inf")
        self.network_calls = 0

    def get(self, url: str, params: Mapping[str, Any] | None = None, headers: Mapping[str, str] | None = None) -> Any:
        """GET ``url`` as JSON, serving from the cache when fresh.

        Retries 429 and 5xx responses with backoff. When offline, a stale cached copy
        is returned if one exists.

        Raises:
            FeedError: if the request fails and there is nothing cached.
        """
        key = HttpCache.key(url, params)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        if self.offline:
            stale = self.cache.get(key, allow_stale=True)
            if stale is not None:
                return stale
            raise FeedError(f"offline and no cached response for {url}")
        last_error = ""
        for attempt in range(self.retries + 1):
            wait = self.min_interval_s - (self.clock() - self._last_call)
            if wait > 0:
                self.sleep(wait)
            self._last_call = self.clock()
            self.network_calls += 1
            try:
                resp = self.session.get(url, params=params, headers=dict(headers or {}), timeout=self.timeout_s)
            except requests.RequestException as exc:
                last_error = type(exc).__name__
            else:
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except ValueError as exc:
                        raise FeedError(f"{url} returned invalid JSON") from exc
                    self.cache.put(key, body)
                    return body
                if resp.status_code not in RETRY_STATUSES:
                    raise FeedError(f"{url} returned HTTP {resp.status_code}")
                last_error = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    self.sleep(min(float(retry_after), 60.0))
            if attempt < self.retries:
                self.sleep(min(2.0 ** attempt, 30.0))
        stale = self.cache.get(key, allow_stale=True)
        if stale is not None:
            logger.warning("%s unavailable (%s); using stale cached copy", url, last_error)
            return stale
        raise FeedError(f"{url} failed after {self.retries + 1} attempts ({last_error})")
