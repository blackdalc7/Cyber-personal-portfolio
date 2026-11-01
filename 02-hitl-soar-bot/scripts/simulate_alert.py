#!/usr/bin/env python3
"""Send a signed alert to the bot, exactly as a SIEM integration would.

    python scripts/simulate_alert.py alerts/samples/ssh_bruteforce.json --url http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv


def main(argv: list[str] | None = None) -> int:
    """Sign the alert file with ``WEBHOOK_SHARED_SECRET`` and POST it to the bot."""
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    ap.add_argument("--url", default=os.getenv("SOAR_URL", "http://127.0.0.1:8080"))
    args = ap.parse_args(argv)
    secret = os.getenv("WEBHOOK_SHARED_SECRET", "")
    if not secret:
        print("error: WEBHOOK_SHARED_SECRET is not set", file=sys.stderr)
        return 2
    body = args.file.read_bytes()
    ts = str(int(time.time()))
    sig = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    ctype = "application/json" if args.file.suffix == ".json" else "text/plain"
    resp = requests.post(f"{args.url.rstrip('/')}/alerts", data=body, timeout=15,
                         headers={"Content-Type": ctype, "X-SOAR-Timestamp": ts, "X-SOAR-Signature": sig})
    print(resp.status_code, resp.text.strip())
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
