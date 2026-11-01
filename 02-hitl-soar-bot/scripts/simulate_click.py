#!/usr/bin/env python3
"""Simulate an analyst clicking a button on a Slack approval card (outbox/demo mode).

Reads the action value from the card the bot wrote to data/outbox, builds a real
Slack ``block_actions`` payload, signs it with SLACK_SIGNING_SECRET and posts it
to /slack/interactions. The bot cannot tell it apart from a genuine Slack callback.

    python scripts/simulate_click.py INC-20261026-1A2B3C4D --decision approve --user U012ANALYST
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv


def find_value(outbox: Path, incident_id: str, action_id: str) -> str:
    """Read the signed button value for ``action_id`` from the incident's latest outbox card."""
    cards = sorted(outbox.glob(f"{incident_id}-*-request.json"))
    if not cards:
        raise SystemExit(f"error: no approval card for {incident_id} in {outbox}")
    for block in json.loads(cards[-1].read_text(encoding="utf-8"))["blocks"]:
        for el in block.get("elements", []):
            if el.get("action_id") == action_id:
                return el["value"]
    raise SystemExit(f"error: card has no {action_id} button")


def main(argv: list[str] | None = None) -> int:
    """Send a Slack-signed Approve or Reject click for an incident, as Slack would."""
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("incident_id")
    ap.add_argument("--decision", choices=["approve", "reject"], default="approve")
    ap.add_argument("--user", default=os.getenv("SIMULATE_USER_ID", "U0DEMOANALYST"))
    ap.add_argument("--name", default="demo.analyst")
    ap.add_argument("--url", default=os.getenv("SOAR_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--outbox", type=Path, default=Path(os.getenv("SOAR_DATA_DIR", "data")) / "outbox")
    args = ap.parse_args(argv)
    secret = os.getenv("SLACK_SIGNING_SECRET", "")
    if not secret:
        print("error: SLACK_SIGNING_SECRET is not set", file=sys.stderr)
        return 2
    action_id = "approve_isolation" if args.decision == "approve" else "reject_isolation"
    payload = {"type": "block_actions", "user": {"id": args.user, "username": args.name},
               "actions": [{"action_id": action_id, "value": find_value(args.outbox, args.incident_id, action_id)}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = str(int(time.time()))
    sig = "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    resp = requests.post(f"{args.url.rstrip('/')}/slack/interactions", data=body, timeout=15,
                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                  "X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig})
    print(resp.status_code)
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
