# n8n playbooks

> Part of the [Threat Response Engineering portfolio](../../README.md). Glue between [Watchfloor](../../watchfloor/README.md), [02's approval service](../../02-hitl-soar-bot/README.md) and [09's evidence collection](../../09-evidence-timeline/README.md).

Two workflows. n8n does the orchestration. 02 stays the only place where a human approves containment, because it already has signed Slack and Discord buttons, an audit chain and expiry. n8n never isolates anything itself.

```
 Watchfloor hub ──GET /api/findings──► [alert intake] ──signed POST /alerts──► 02 ──Slack/Discord buttons──► analyst
                                                                                │
                                         signed decision webhook ◄──────────────┘
                                                    │
                                           [decision follow-up] ──signed POST /collect──► 09 (Velociraptor + Hayabusa)
                                                    └────────────── POST ──► team channel
```

| Workflow | Trigger | What it does |
|---|---|---|
| **Watchfloor: alert intake** | every minute | Reads the last 5 minutes of Detection Findings at or above `MIN_SEVERITY_ID` (default 4, high). Drops ones it has already sent in the last 6 hours and 02's own findings, so nothing loops. Adds host context (other findings on the host in the last hour), signs the alert and opens an incident in 02. |
| **Watchfloor: decision follow-up** | `POST /webhook/watchfloor-decision` from 02 | Verifies 02's signature over the raw body, refuses stale timestamps and replays, and answers `401` to anything unsigned. On `incident.approved` it signs a `/collect` request to 09 for that host and incident. Every decision (approved, rejected, remediated, failed, expired) goes to the channel. |

## Signing

Every hop uses the same scheme as 02's inbound alerts, each with its own secret:

```
X-SOAR-Timestamp: <unix seconds>
X-SOAR-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>." + body)>
```

| Hop | Secret (`deploy/.env`) |
|---|---|
| n8n → 02 `/alerts` | `WEBHOOK_SHARED_SECRET` (n8n sees it as `SOAR_WEBHOOK_SECRET`) |
| 02 → n8n decision webhook | `DECISION_WEBHOOK_SECRET` |
| n8n → 09 `/collect` | `EVIDENCE_SHARED_SECRET` |

Bodies are sent with `contentType: raw` so the bytes on the wire are the bytes that were signed. The decision webhook has `rawBody` on for the same reason: re-serialising 02's JSON in JavaScript changes it (`1.0` becomes `1`), so the verifier refuses any request whose raw body is missing rather than guessing.

## Install

The `automation` profile in [`deploy/`](../../deploy/README.md) runs n8n with these exports mounted read-only at `/workflows` and the variables the Code nodes read already set (`WF_HUB_URL`, `SOAR_URL`, `EVIDENCE_URL` and the three secrets). `NODE_FUNCTION_ALLOW_BUILTIN=crypto` lets the Code nodes compute HMACs and nothing else.

```bash
cd deploy
# .env: N8N_ENCRYPTION_KEY, WEBHOOK_SHARED_SECRET, DECISION_WEBHOOK_SECRET, EVIDENCE_SHARED_SECRET (each >= 32 chars,
#       all different), DECISION_WEBHOOK_URL=http://n8n:5678/webhook/watchfloor-decision, NOTIFY_WEBHOOK_URL (optional)
docker compose --profile automation --profile dfir up -d
docker compose exec n8n n8n import:workflow --separate --input=/workflows
docker compose exec n8n n8n update:workflow --all --active=true
docker compose restart n8n
```

The exports are imported inactive on purpose. Activate them once the secrets are set; until then the Code nodes refuse to sign with an empty or short secret.

`NOTIFY_WEBHOOK_URL` can be a Slack incoming webhook or a Discord webhook; the message carries both `text` and `content`, and each service reads its own.

## Editing

The JavaScript lives in [`code/`](code) as plain files, and [`build_workflows.py`](build_workflows.py) stitches it into the exports in [`workflows/`](workflows). Change the `.js`, then:

```bash
python automation/n8n/build_workflows.py           # regenerate workflows/*.json
python automation/n8n/build_workflows.py --check   # CI: fail if the exports are stale
```

If you edit a workflow in the n8n editor instead, copy the Code node back into `code/` and regenerate, or the next build overwrites it.

| File | Node |
|---|---|
| `new_findings.js` | dedupe by finding uid in workflow static data (6 h), Detection Findings only, never 02's own |
| `build_alert.js` | 02's generic alert format, host context from the hub, HMAC |
| `verify_decision.js` | raw-body HMAC, 300 s skew, constant-time compare, replay cache (10 min) |
| `plan_actions.js` | channel text per event, signed `/collect` request on approval |

## Tests

```bash
pytest automation/n8n/tests      # 23 tests; needs node on PATH
```

`tests/run_code.mjs` runs each Code node under Node with n8n's globals (`$env`, `$input`, `$getWorkflowStaticData`, `this.helpers.httpRequest`) stubbed, and with `require` limited to `crypto`. The Python tests then check the output against the real verifiers: an alert built in JavaScript must pass 02's `verify_body` and `normalise`, a decision signed by 02's `DecisionWebhook` code must pass `verify_decision.js`, and a collection request must pass 09's `Verifier` and `CollectRequest` validation. They also check tampering, replays, stale timestamps, missing secrets and the shape of both exports (every connection points at a real node, an unsigned request ends at the `401`).

## Limits

- The exports target n8n 1.x (pinned `1.121.0` in compose): Code v2, HTTP Request v4.2, Webhook v2, If v2. They were validated structurally and their code executed under Node; they have not been imported into a running n8n in the environment this was built in (no Docker there).
- Static data (the dedupe and replay caches) is only persisted for active, production executions. A manual test run in the editor starts with empty caches.
- Tines: the same contract ports directly (an HTTP Request action with `HMAC_SHA256` in the headers, a webhook action with a signature check). No Tines story is included.
