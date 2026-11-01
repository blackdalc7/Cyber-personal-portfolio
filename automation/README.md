# Automation

> Part of the [Threat Response Engineering portfolio](../README.md).

SOAR playbooks that connect the platform's pieces. They run in the `automation` profile of [`deploy/`](../deploy/README.md).

| Folder | What |
|---|---|
| [`n8n/`](n8n/README.md) | Alert intake (Watchfloor findings → 02 approval) and decision follow-up (02 decision → 09 evidence collection → team channel), with the Code-node JavaScript as testable source files |

The split of responsibilities is deliberate:

- **n8n orchestrates.** Polling, enrichment, fan-out and notifications are easy to change in a workflow editor.
- **02 decides.** The human approval for containment stays in [02-hitl-soar-bot](../02-hitl-soar-bot/README.md), with signed chat buttons, an audit hash chain and expiry. Nothing here can isolate a host.
- **Every hop is signed.** n8n → 02, 02 → n8n and n8n → 09 each use HMAC-SHA256 over timestamp and raw body with a separate secret, and every receiver refuses stale or replayed requests.
