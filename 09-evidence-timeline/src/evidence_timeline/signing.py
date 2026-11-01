"""HMAC request signing, the same scheme 02 uses for alerts and decisions.

    X-SOAR-Timestamp: <unix seconds>
    X-SOAR-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>." + body)>

Timestamps older or newer than five minutes are refused, and a signature seen once inside that window is refused
the second time, so a captured request cannot be replayed to start another collection.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections.abc import Callable

MAX_SKEW_S = 300


def sign(secret: str, body: bytes, timestamp: int | None = None) -> tuple[str, str]:
    ts = str(int(time.time()) if timestamp is None else timestamp)
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return ts, f"sha256={mac}"


class Verifier:
    """Checks SOAR request signatures: HMAC-SHA256 over ``timestamp.body``, bounded clock skew, no replays."""
    def __init__(self, secret: str, clock: Callable[[], float] = time.time) -> None:
        self._secret = secret
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def verify(self, body: bytes, timestamp: str | None, signature: str | None) -> bool:
        """True only for a correct signature with a fresh timestamp that has not been seen before."""
        if not self._secret or not timestamp or not signature or not signature.startswith("sha256="):
            return False
        try:
            ts = int(timestamp)
        except ValueError:
            return False
        now = self._clock()
        if abs(now - ts) > MAX_SKEW_S:
            return False
        expected = hmac.new(self._secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature[len("sha256="):]):
            return False
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v > now - 2 * MAX_SKEW_S}
            if signature in self._seen:
                return False
            self._seen[signature] = now
        return True
