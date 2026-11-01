"""Generate the n8n workflow exports in workflows/ from the Code-node sources in code/.

The JavaScript lives in plain .js files so it can be reviewed, linted and unit-tested (tests/run_code.mjs runs it
under Node with n8n's globals stubbed). This script stitches it into importable n8n workflow JSON:

    python build_workflows.py            # rewrite workflows/*.json
    python build_workflows.py --check    # exit 1 if the committed exports are stale (CI)

Import into n8n with ``n8n import:workflow --separate --input=/workflows`` (the compose service mounts the folder).
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CODE = HERE / "code"
OUT = HERE / "workflows"
NS = uuid.UUID("5b0c7a52-31f4-4f0e-9a43-6f1d7bd0c0de")  # stable node ids, so re-generating gives a clean diff


def node(workflow: str, name: str, type_: str, version: float, position: tuple[int, int],
         parameters: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"parameters": parameters, "id": str(uuid.uuid5(NS, f"{workflow}/{name}")), "name": name,
            "type": f"n8n-nodes-base.{type_}", "typeVersion": version, "position": list(position), **extra}


def code_node(workflow: str, name: str, file: str, position: tuple[int, int]) -> dict[str, Any]:
    return node(workflow, name, "code", 2, position, {"jsCode": (CODE / file).read_text(encoding="utf-8")})


def header(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}


def signed_post(workflow: str, name: str, url: str, body: str, ts: str, sig: str,
                position: tuple[int, int]) -> dict[str, Any]:
    """POST a pre-serialised body with the X-SOAR-* headers. The body is sent raw so the bytes match the HMAC."""
    return node(workflow, name, "httpRequest", 4.2, position, {
        "method": "POST",
        "url": url,
        "sendHeaders": True,
        "headerParameters": {"parameters": [
            header("X-SOAR-Timestamp", ts),
            header("X-SOAR-Signature", sig),
        ]},
        "sendBody": True,
        "contentType": "raw",
        "rawContentType": "application/json",
        "body": body,
        "options": {"timeout": 15000},
    }, retryOnFail=True, maxTries=3, waitBetweenTries=2000)


def connect(*pairs: tuple[str, str] | tuple[str, str, int]) -> dict[str, Any]:
    """connect(("A", "B"), ("IF", "C", 1)) -> n8n's connections map. The third value is the source output index."""
    out: dict[str, Any] = {}
    for pair in pairs:
        src, dst = pair[0], pair[1]
        index = pair[2] if len(pair) == 3 else 0  # type: ignore[misc]
        outputs = out.setdefault(src, {"main": []})["main"]
        while len(outputs) <= index:
            outputs.append([])
        outputs[index].append({"node": dst, "type": "main", "index": 0})
    return out


def workflow(name: str, nodes: list[dict[str, Any]], connections: dict[str, Any], tags: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "nodes": nodes,
        "connections": connections,
        "active": False,  # activate after import, once the secrets in deploy/.env are set
        "settings": {"executionOrder": "v1", "saveDataErrorExecution": "all", "saveDataSuccessExecution": "none",
                     "callerPolicy": "workflowsFromSameOwner"},
        "pinData": {},
        "tags": [{"name": t} for t in tags],
        "meta": {"generatedBy": "automation/n8n/build_workflows.py"},
    }


def alert_intake() -> dict[str, Any]:
    """The alert-intake workflow: every minute, send new hub findings to 02 as signed alerts."""
    w = "alert-intake"
    nodes = [
        node(w, "Every minute", "scheduleTrigger", 1.2, (0, 0),
             {"rule": {"interval": [{"field": "minutes", "minutesInterval": 1}]}}),
        node(w, "Recent findings", "httpRequest", 4.2, (220, 0), {
            "method": "GET",
            "url": "={{ $env.WF_HUB_URL }}/api/findings",
            "sendQuery": True,
            "queryParameters": {"parameters": [
                header("since", "={{ Date.now() - 5 * 60 * 1000 }}"),
                header("min_severity", "={{ $env.MIN_SEVERITY_ID || 4 }}"),
                header("limit", "500"),
            ]},
            "sendHeaders": True,
            "headerParameters": {"parameters": [header("Authorization", "=Bearer {{ $env.WF_HUB_TOKEN }}")]},
            "options": {"timeout": 15000},
        }),
        code_node(w, "New findings only", "new_findings.js", (440, 0)),
        code_node(w, "Build signed alert", "build_alert.js", (660, 0)),
        signed_post(w, "Open incident in 02", "={{ $env.SOAR_URL }}/alerts", "={{ $json.body }}",
                    "={{ $json.ts }}", "={{ $json.sig }}", (880, 0)),
    ]
    return workflow("Watchfloor: alert intake", nodes, connect(
        ("Every minute", "Recent findings"),
        ("Recent findings", "New findings only"),
        ("New findings only", "Build signed alert"),
        ("Build signed alert", "Open incident in 02"),
    ), ["watchfloor", "soar"])


def _if(w: str, name: str, left: str, position: tuple[int, int]) -> dict[str, Any]:
    return node(w, name, "if", 2, position, {
        "conditions": {
            "options": {"caseSensitive": True, "typeValidation": "strict"},
            "conditions": [{"id": str(uuid.uuid5(NS, f"{w}/{name}/cond")), "leftValue": left, "rightValue": "",
                            "operator": {"type": "boolean", "operation": "true", "singleValue": True}}],
            "combinator": "and",
        },
        "options": {},
    })


def decision() -> dict[str, Any]:
    """The decision workflow: verify 02's signed decision, plan the approved actions and post them to chat."""
    w = "decision"
    nodes = [
        node(w, "02 decision webhook", "webhook", 2, (0, 0), {
            "httpMethod": "POST",
            "path": "watchfloor-decision",
            "responseMode": "responseNode",
            "options": {"rawBody": True},
        }, webhookId=str(uuid.uuid5(NS, f"{w}/webhook"))),
        code_node(w, "Verify signature", "verify_decision.js", (220, 0)),
        _if(w, "Signed by 02?", "={{ $json.valid }}", (440, 0)),
        node(w, "Accept", "respondToWebhook", 1.1, (660, -120), {"respondWith": "noData",
                                                              "options": {"responseCode": 204}}),
        node(w, "Refuse", "respondToWebhook", 1.1, (660, 120), {
            "respondWith": "json",
            "responseBody": '={{ JSON.stringify({ error: "invalid signature" }) }}',
            "options": {"responseCode": 401},
        }),
        code_node(w, "Plan actions", "plan_actions.js", (880, -120)),
        _if(w, "Collect evidence?", "={{ $json.collect }}", (1100, -120)),
        signed_post(w, "Start collection in 09", "={{ $env.EVIDENCE_URL }}/collect", "={{ $json.collect_body }}",
                    "={{ $json.collect_ts }}", "={{ $json.collect_sig }}", (1320, -220)),
        _if(w, "Notify?", "={{ $('Plan actions').item.json.notify }}", (1540, -120)),
        node(w, "Post to channel", "httpRequest", 4.2, (1760, -120), {
            "method": "POST",
            "url": "={{ $env.NOTIFY_WEBHOOK_URL }}",
            "sendBody": True,
            "specifyBody": "json",
            # Slack incoming webhooks read "text", Discord webhooks read "content"; each ignores the other.
            "jsonBody": "={{ JSON.stringify({ text: $('Plan actions').item.json.text, "
                        "content: $('Plan actions').item.json.text }) }}",
            "options": {"timeout": 10000},
        }, continueOnFail=True),
    ]
    # Collection failures must not stop the channel notification, so the 09 call continues on fail.
    nodes[7]["continueOnFail"] = True
    return workflow("Watchfloor: decision follow-up", nodes, connect(
        ("02 decision webhook", "Verify signature"),
        ("Verify signature", "Signed by 02?"),
        ("Signed by 02?", "Accept", 0),
        ("Signed by 02?", "Refuse", 1),
        ("Accept", "Plan actions"),
        ("Plan actions", "Collect evidence?"),
        ("Collect evidence?", "Start collection in 09", 0),
        ("Collect evidence?", "Notify?", 1),
        ("Start collection in 09", "Notify?"),
        ("Notify?", "Post to channel", 0),
    ), ["watchfloor", "soar", "dfir"])


WORKFLOWS = {"watchfloor-alert-intake.json": alert_intake, "watchfloor-decision.json": decision}


def render() -> dict[str, str]:
    return {name: json.dumps(build(), indent=2, ensure_ascii=False) + "\n" for name, build in WORKFLOWS.items()}


def main() -> int:
    """Write the workflow exports, or with ``--check`` exit 1 if any committed export is stale."""
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if workflows/ differs from the sources")
    args = ap.parse_args()
    stale = []
    for name, text in render().items():
        path = OUT / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            OUT.mkdir(exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(HERE)}")
    if stale:
        print(f"stale: {', '.join(stale)}; run python automation/n8n/build_workflows.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
