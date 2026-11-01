# 02 · HitL SOAR Bot

> Part of the [Threat Response Engineering portfolio](../README.md). This folder is self-contained and can also be published as its own repository.

A containerised SOAR bot that **will not isolate a host until an authorised analyst clicks "Approve Isolation"** in Slack or Discord. It turns alerts into incidents, enriches them, posts an interactive approval card, and waits durably for the signed callback. It then runs the remediation script exactly once and updates the card. Every stage is timed in SQLite, so the team can report MTTA, approval latency, time-to-contain and MTTR.

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Run it with Docker

```bash
cd 02-hitl-soar-bot
cp .env.example .env
# set WEBHOOK_SHARED_SECRET, SOAR_API_TOKEN, SLACK_SIGNING_SECRET and SLACK_APPROVER_IDS
docker compose up --build -d
curl -s localhost:8080/healthz
```

### Demo the full loop without a Slack workspace (outbox mode)

With no bot token configured, cards are written to `data/outbox/` and you play the analyst:

```bash
export $(grep -v '^#' .env | xargs)          # same secrets the container uses
python scripts/simulate_alert.py alerts/samples/ssh_bruteforce.json
# → 201 {"incident_id":"INC-20261026-1A2B3C4D","status":"awaiting_approval"}

docker compose cp soar-bot:/data/outbox ./outbox
python scripts/simulate_click.py INC-20261026-1A2B3C4D --user "$SLACK_APPROVER_IDS" --outbox ./outbox
curl -s -H "Authorization: Bearer $SOAR_API_TOKEN" localhost:8080/incidents/INC-20261026-1A2B3C4D
curl -s -H "Authorization: Bearer $SOAR_API_TOKEN" localhost:8080/metrics/mttr
```

`simulate_click.py` sends a genuinely signed Slack `block_actions` payload, so this exercises the same verification path a real click uses.

### Connect a real Slack workspace

1. Create an app from [docs/slack-app-manifest.yml](docs/slack-app-manifest.yml) and replace the request URL with your HTTPS endpoint, using a reverse proxy or a tunnel such as `cloudflared`.
2. Install it to the workspace and invite the bot to the SOC channel.
3. Set `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `SLACK_CHANNEL_ID` and `SLACK_APPROVER_IDS` in `.env`, then run `docker compose up -d`.

For Discord, set `DISCORD_BOT_TOKEN`, `DISCORD_PUBLIC_KEY`, `DISCORD_CHANNEL_ID` and `DISCORD_APPROVER_IDS`, and point the application's Interactions Endpoint URL at `/discord/interactions`.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/alerts` | HMAC (`X-SOAR-Timestamp`, `X-SOAR-Signature`) | Intake. Accepts generic JSON, ECS alerts or chain docs from Project 01, or plain text |
| `POST` | `/slack/interactions` | Slack v0 signature | Button callbacks |
| `POST` | `/discord/interactions` | Ed25519 signature | Button callbacks |
| `GET` | `/incidents[?status=]` | Bearer `SOAR_API_TOKEN` | List incidents |
| `GET` | `/incidents/<id>` | Bearer | Incident plus its audit trail |
| `GET` | `/metrics/mttr[?since=epoch]` | Bearer | KPI report |
| `GET` | `/audit/verify` | Bearer | Recompute the audit hash chain |
| `GET` | `/healthz` | none | Liveness |

### Outbound: the decision webhook

Set `DECISION_WEBHOOK_URL` and `DECISION_WEBHOOK_SECRET` and the bot tells the rest of the platform what a human decided. Each time an incident is approved, rejected, remediated, fails remediation or expires, it POSTs:

```json
{"event": "incident.approved", "sent_at": 1793001234.5,
 "incident": {"id": "INC-20261026-1A2B3C4D", "host": "web01", "status": "approved", "decided_by": "alice", ...}}
```

signed the same way as inbound alerts (`X-SOAR-Timestamp`, `X-SOAR-Signature: sha256=HMAC("<ts>." + body)`), plus `X-SOAR-Event`. The secret must differ from `WEBHOOK_SHARED_SECRET`, so whoever receives decisions cannot forge alerts, and the event never carries the approval nonce. Delivery runs off the request path with three attempts and exponential back-off; 4xx answers other than 429 are not retried, and every outcome is written to the audit trail. The decision itself never depends on the webhook. Events can arrive out of order (`approved` and `remediated` are sent from different workers), so receivers should key on `incident.status` and the timestamps.

In the portfolio, n8n receives this and starts evidence collection in [09](../09-evidence-timeline/README.md) after an approved containment.

## Tests

```bash
pip install -r requirements-dev.txt
pytest --cov          # 79 tests, coverage gate 85%
```

The suite covers:

- Signature and replay rejection.
- Unauthorised approvers and forged nonces.
- Double-click and 8-way concurrent approval races.
- Reject, expiry, remediation failure and chat-outage paths.
- Shell-injection attempts and the child-process secret scrub.
- Audit tampering, including with the triggers dropped.
- MTTR maths.
- The outbound decision webhook: signatures, no nonce leak, retries, audit, config validation.
- Slack, Discord and AbuseIPDB HTTP contracts.
- A full real-HTTP loop: waitress, then `simulate_alert.py`, then `simulate_click.py`, ending in the isolation record.

## Project layout

```text
02-hitl-soar-bot/
├── src/soar_bot/
│   ├── server.py          wiring and CLI entry point (waitress)
│   ├── app.py             Flask routes: alert intake, chat callbacks, read API
│   ├── service.py         the approval workflow and remediation hand-off
│   ├── db.py              SQLite incidents, state machine, hash-chained audit log, MTTR
│   ├── ingest.py          normalises text, ECS and generic JSON alerts
│   ├── enrichment.py      AbuseIPDB lookups with caching (public IPs only)
│   ├── remediation.py     runs the isolation script safely as a subprocess
│   ├── decision_hook.py   signed outbound decision events for n8n
│   ├── report.py          MTTA / MTTR report CLI
│   ├── config.py          settings and startup validation
│   └── chat/              Slack, Discord and offline "outbox" approval cards
├── scripts/               mock isolation, alert and click simulators for the demo
├── alerts/samples/        example alerts
├── tests/                 pytest suite
├── docs/                  ARCHITECTURE.md and the Slack app manifest
├── Dockerfile, docker-compose.yml
└── .env.example
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt ruff
ruff check .            # lint, using this folder's ruff.toml (includes security rules)
pytest --cov            # tests with the 85% coverage gate
```

Every module, class and public function has a docstring explaining what it does,
its arguments and the errors it raises. Start reading at `docs/ARCHITECTURE.md`,
then the entry point named in the layout above.

CI (`.github/workflows/ci.yml`) runs lint and tests on Python 3.10 and 3.13,
`pip-audit` on the runtime dependencies, and a non-root Docker build.

## Licence

MIT. See [LICENSE](LICENSE).
