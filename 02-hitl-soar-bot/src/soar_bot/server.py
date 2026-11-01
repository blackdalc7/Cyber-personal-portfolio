"""Process entry point: build every component from Settings and serve with waitress."""

from __future__ import annotations

import argparse
import logging
import sys

from .app import create_app
from .chat import DiscordChat, OutboxChat, SlackChat
from .chat.base import ChatProvider
from .config import ConfigError, Settings
from .db import Database
from .decision_hook import DecisionWebhook
from .enrichment import Enricher
from .remediation import Remediator
from .service import SoarService

logger = logging.getLogger("soar_bot")


def build_chat(settings: Settings) -> tuple[ChatProvider, frozenset[str]]:
    """Pick the chat provider and its approver allow-list from the settings."""
    if settings.chat_mode == "slack":
        return SlackChat(settings.slack_bot_token, settings.slack_channel), settings.slack_approver_ids
    if settings.chat_mode == "discord":
        return DiscordChat(settings.discord_bot_token, settings.discord_channel_id), settings.discord_approver_ids
    # Outbox mode accepts signed Slack-format callbacks from the local simulator.
    return OutboxChat(settings.data_dir / "outbox"), settings.slack_approver_ids


def build_service(settings: Settings) -> SoarService:
    """Wire up the database, chat, enrichment and remediation into a :class:`SoarService`."""
    chat, approvers = build_chat(settings)
    return SoarService(
        db=Database(settings.database_path),
        chat=chat,
        enricher=Enricher(settings.abuseipdb_api_key, settings.intel_timeout_s),
        remediator=Remediator(settings.remediation_script, settings.data_dir / "isolation_state.json",
                              settings.remediation_timeout_s, settings.dry_run),
        approvers=approvers,
        approval_ttl_s=settings.approval_ttl_s,
        min_severity=settings.min_severity_for_approval,
        decision_hook=(DecisionWebhook(settings.decision_webhook_url, settings.decision_webhook_secret)
                       if settings.decision_webhook_url else None),
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: load settings, start the expiry sweeper and serve with waitress."""
    ap = argparse.ArgumentParser(prog="soar-bot", description="Human-in-the-Loop SOAR bot")
    ap.add_argument("--env-file")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = Settings.from_env(dotenv_path=args.env_file)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    service = build_service(settings)
    service.run_expiry_loop(settings.expiry_sweep_s)
    app = create_app(settings, service)
    logger.info("HitL SOAR bot on http://%s:%s (chat=%s, approvers=%d)", settings.listen_host,
                settings.listen_port, service.chat.name, len(service.approvers))
    from waitress import serve
    try:
        serve(app, host=settings.listen_host, port=settings.listen_port, threads=args.threads,
              max_request_body_size=settings.max_body_bytes, ident="soar-bot")
    finally:
        service.shutdown()
    return 0
