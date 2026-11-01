"""Shared pytest fixtures: settings, fake clock, outbox chat, database, service and Flask client."""

from __future__ import annotations

from dataclasses import replace

import pytest
from helpers import APPROVER, SLACK_SECRET, WEBHOOK_SECRET, FakeClock, RecordingChat, SyncExecutor

from soar_bot.app import create_app
from soar_bot.config import Settings
from soar_bot.db import Database
from soar_bot.enrichment import Enricher
from soar_bot.remediation import Remediator
from soar_bot.service import SoarService


@pytest.fixture
def settings(tmp_path):
    return replace(Settings(), data_dir=tmp_path, database_path=tmp_path / "soar.db",
                   webhook_secret=WEBHOOK_SECRET, slack_signing_secret=SLACK_SECRET,
                   slack_approver_ids=frozenset({APPROVER}), api_token="t" * 32)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def chat():
    return RecordingChat()


@pytest.fixture
def db(settings, clock):
    return Database(settings.database_path, clock=clock)


@pytest.fixture
def service(settings, db, chat, clock):
    return SoarService(db=db, chat=chat, enricher=Enricher(""),
                       remediator=Remediator(settings.remediation_script, settings.data_dir / "iso.json", 30),
                       approvers=settings.slack_approver_ids, approval_ttl_s=600, executor=SyncExecutor(),
                       clock=clock)


@pytest.fixture
def client(settings, service):
    app = create_app(settings, service)
    app.testing = True
    return app.test_client()
