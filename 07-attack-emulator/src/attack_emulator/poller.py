"""Ask the Watchfloor hub whether a technique was detected, with exponential backoff and full jitter."""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

FINDING_CLASSES = {2004, 2005}


def technique_matches(wanted: str, seen: str) -> bool:
    a, b = wanted.upper(), seen.upper()
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


class HubClient:
    """Minimal read client for the Watchfloor hub's findings, events and health endpoints."""
    def __init__(self, base_url: str, token: str = "", client: httpx.Client | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = client or httpx.Client(timeout=10.0)

    def _get(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        r = self._client.get(f"{self._base}{path}", params={k: v for k, v in params.items() if v is not None},
                             headers=self._headers)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def findings(self, since_ms: int, technique: str, hostname: str | None = None) -> list[dict[str, Any]]:
        rows = self._get("/api/findings", {"since": since_ms, "technique": technique.split(".")[0], "limit": 100})
        return [r for r in rows if any(technique_matches(technique, t) for t in r.get("techniques") or [])
                and (hostname is None or (r.get("hostname") or "").lower() == hostname.lower())]

    def telemetry(self, since_ms: int, until_ms: int, hostname: str, match: str | None = None) -> list[dict[str, Any]]:
        rows = self._get("/api/events", {"since": since_ms, "until": until_ms, "hostname": hostname, "q": match,
                                         "limit": 500})
        return [r for r in rows if r.get("class_uid") not in FINDING_CLASSES]

    def health(self) -> dict[str, Any]:
        r = self._client.get(f"{self._base}/api/health")
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._client.close()


@dataclass
class Observation:
    """What the hub showed for one technique during its scoring window."""
    outcome: str  # detected | telemetry_only | missed | error
    ttd_ms: int | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    telemetry_events: int = 0
    polls: int = 0
    errors: list[str] = field(default_factory=list)


def backoff_delays(base: float, cap: float, rng: random.Random) -> Callable[[int], float]:
    """Full-jitter exponential backoff: attempt n waits uniform(base/2, min(cap, base * 2**n))."""
    def delay(n: int) -> float:
        hi = min(cap, base * (2 ** n))
        return rng.uniform(min(base / 2, hi), hi)
    return delay


def wait_for_detection(hub: HubClient, *, technique: str, hostname: str, start_ms: int, timeout_s: float,
                       base_s: float, max_s: float, window_s: float, clock: Callable[[], float] | None = None,
                       sleep: Callable[[float], None] | None = None, rng: random.Random | None = None,
                       match: str | None = None) -> Observation:
    """Poll until a matching finding shows up or ``timeout_s`` passes, then classify the stage.

    Telemetry is counted from just before the technique ran until now, which is before its cleanup and before the
    next technique starts. ``match`` narrows it to events whose message or command line contains that text, so
    background noise on a busy host does not turn every miss into "telemetry only".
    """
    clock = clock or time.time
    sleep = sleep or time.sleep
    delay = backoff_delays(base_s, max_s, rng or random.Random())
    deadline = clock() + timeout_s
    since = start_ms - 1000
    obs = Observation("missed")
    attempt = 0
    poll_errors = 0
    while True:
        obs.polls += 1
        try:
            hits = [f for f in hub.findings(since, technique, hostname)
                    if since <= int(f["time"]) <= start_ms + int(window_s * 1000)]
        except (httpx.HTTPError, ValueError) as exc:
            hits = []
            poll_errors += 1
            obs.errors.append(type(exc).__name__)
        if hits:
            hits.sort(key=lambda f: int(f["time"]))
            obs.outcome = "detected"
            obs.ttd_ms = max(0, int(hits[0]["time"]) - start_ms)
            obs.findings = [{"title": f.get("finding_title"), "product": f.get("product"), "time": f.get("time"),
                             "uid": f.get("uid")} for f in hits[:10]]
            break
        if clock() >= deadline:
            break
        sleep(max(0.0, min(delay(attempt), deadline - clock())))
        attempt += 1
    try:
        obs.telemetry_events = len(hub.telemetry(since, int(clock() * 1000), hostname, match))
    except (httpx.HTTPError, ValueError) as exc:
        obs.errors.append(type(exc).__name__)
    if obs.outcome != "detected":
        if poll_errors == obs.polls and not obs.telemetry_events:
            obs.outcome = "error"  # the hub never answered: we know nothing, so do not call it a miss
        elif obs.telemetry_events:
            obs.outcome = "telemetry_only"
    return obs
