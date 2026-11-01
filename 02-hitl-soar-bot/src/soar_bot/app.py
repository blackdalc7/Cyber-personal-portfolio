"""Flask application: alert intake, chat callbacks, and the read API."""

from __future__ import annotations

import hmac
import json
import logging
from typing import Any
from urllib.parse import urlparse

import requests
from flask import Flask, Response, abort, jsonify, request

from .chat import discord as discord_chat
from .chat import slack as slack_chat
from .chat.base import parse_action_value
from .config import Settings
from .ingest import AlertError, normalise, verify_body
from .service import SoarService

logger = logging.getLogger("soar_bot.app")

SLACK_RESPONSE_HOSTS = {"hooks.slack.com"}


def create_app(settings: Settings, service: SoarService, http: requests.Session | None = None) -> Flask:
    """Build the Flask application with every HTTP route wired to ``service``.

    Routes:
        ``POST /alerts``: HMAC-signed alert intake.
        ``POST /slack/interactions`` and ``POST /discord/interactions``: signed button callbacks.
        ``GET /incidents``, ``/incidents/<id>``, ``/metrics/mttr``, ``/audit/verify``: read API,
        protected by a bearer token.
        ``GET /healthz``: liveness probe.

    ``http`` is the session used for Slack ephemeral replies, injectable for tests.
    """
    app = Flask("soar_bot")
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    http = http or requests.Session()

    def require_api_token() -> None:
        """Abort with 403 if the read API is disabled, or 401 if the bearer token is wrong."""
        if not settings.api_token:
            abort(403, "read API disabled: set SOAR_API_TOKEN")
        header = request.headers.get("Authorization", "")
        if not hmac.compare_digest(header, f"Bearer {settings.api_token}"):
            abort(401)

    @app.after_request
    def security_headers(resp: Response) -> Response:
        """Add defensive headers to every response."""
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = "default-src 'none'"
        return resp

    @app.get("/healthz")
    def healthz():
        """Liveness probe: report status and the active chat provider."""
        return jsonify(status="ok", chat=service.chat.name)

    # -- alert intake ------------------------------------------------------
    @app.post("/alerts")
    def receive_alert():
        """Verify the HMAC signature, normalise the alert and open an incident."""
        raw = request.get_data(cache=False)
        if not verify_body(settings.webhook_secret, raw, request.headers.get("X-SOAR-Timestamp"),
                           request.headers.get("X-SOAR-Signature")):
            logger.warning("Rejected unsigned/invalid alert from %s", request.remote_addr)
            abort(401)
        if request.mimetype == "application/json":
            try:
                data: Any = json.loads(raw)
            except ValueError:
                abort(400, "invalid JSON")
        else:
            data = raw.decode("utf-8", errors="replace")
        try:
            alert = normalise(data, received_at=service.clock())
        except AlertError as exc:
            abort(400, str(exc))
        incident, created = service.handle_alert(alert)
        return jsonify(incident_id=incident.id, status=incident.status, duplicate=not created), 201 if created else 200

    # -- Slack -------------------------------------------------------------
    @app.post("/slack/interactions")
    def slack_interactions():
        """Handle an Approve or Reject button press from Slack."""
        raw = request.get_data(cache=True)
        if not slack_chat.verify_signature(settings.slack_signing_secret, raw,
                                           request.headers.get("X-Slack-Request-Timestamp"),
                                           request.headers.get("X-Slack-Signature")):
            abort(401)
        try:
            payload = json.loads(request.form.get("payload", ""))
            decision, value, user_id, user_name = slack_chat.parse_interaction(payload)
            incident_id, nonce = parse_action_value(value)
        except (ValueError, TypeError):
            abort(400, "unsupported interaction")
        outcome = service.decide(incident_id, nonce, decision, user_id, user_name, "slack")
        if not outcome.accepted:
            _slack_ephemeral(http, payload.get("response_url"), outcome.message)
        # Slack requires an HTTP 200 within 3 s; the card itself is updated via chat.update.
        return Response(status=200)

    # -- Discord -----------------------------------------------------------
    @app.post("/discord/interactions")
    def discord_interactions():
        """Handle Discord's PING handshake and Approve or Reject button presses."""
        raw = request.get_data(cache=False)
        if not discord_chat.verify_signature(settings.discord_public_key, raw,
                                             request.headers.get("X-Signature-Timestamp"),
                                             request.headers.get("X-Signature-Ed25519")):
            abort(401)
        try:
            payload = json.loads(raw)
        except ValueError:
            abort(400)
        if payload.get("type") == discord_chat.PING:
            return jsonify(type=discord_chat.PONG)
        try:
            decision, value, user_id, user_name = discord_chat.parse_interaction(payload)
            incident_id, nonce = parse_action_value(value)
        except ValueError:
            abort(400, "unsupported interaction")
        outcome = service.decide(incident_id, nonce, decision, user_id, user_name, "discord")
        if outcome.accepted and outcome.incident:
            return jsonify(type=discord_chat.UPDATE_MESSAGE, data=discord_chat.build_message(outcome.incident))
        return jsonify(type=discord_chat.CHANNEL_MESSAGE,
                       data={"content": outcome.message, "flags": discord_chat.EPHEMERAL,
                             "allowed_mentions": {"parse": []}})

    # -- read API ----------------------------------------------------------
    @app.get("/incidents")
    def list_incidents():
        """List incidents, newest first, optionally filtered by ``status``."""
        require_api_token()
        status = request.args.get("status")
        limit = min(max(request.args.get("limit", 100, type=int), 1), 1000)
        return jsonify([i.to_dict() for i in service.db.list(status, limit)])

    @app.get("/incidents/<incident_id>")
    def get_incident(incident_id: str):
        """Return one incident with its full audit trail."""
        require_api_token()
        try:
            incident = service.db.get(incident_id)
        except KeyError:
            abort(404)
        return jsonify(incident=incident.to_dict(), audit=service.db.audit_trail(incident_id))

    @app.get("/metrics/mttr")
    def mttr():
        """Return MTTA and MTTR statistics, optionally only since an epoch timestamp."""
        require_api_token()
        since = request.args.get("since", type=float)
        return jsonify(service.metrics(since))

    @app.get("/audit/verify")
    def audit_verify():
        """Check the audit log's hash chain. Returns 409 if it has been tampered with."""
        require_api_token()
        ok, bad = service.db.verify_audit_chain()
        return jsonify(intact=ok, first_bad_seq=bad), 200 if ok else 409

    @app.errorhandler(413)
    def too_large(_):
        """Return JSON instead of HTML when the body exceeds ``MAX_BODY_BYTES``."""
        return jsonify(error="payload too large"), 413

    return app


def _slack_ephemeral(http: requests.Session, response_url: str | None, text: str) -> None:
    """Tell only the clicking user why their click was refused. SSRF-guarded to Slack's own host."""
    if not response_url:
        return
    parsed = urlparse(response_url)
    if parsed.scheme != "https" or parsed.hostname not in SLACK_RESPONSE_HOSTS:
        logger.warning("Ignoring non-Slack response_url %r", response_url)
        return
    try:
        http.post(response_url, json={"response_type": "ephemeral", "replace_original": False, "text": text},
                  timeout=5)
    except requests.RequestException as exc:
        logger.warning("Slack ephemeral reply failed: %s", type(exc).__name__)
