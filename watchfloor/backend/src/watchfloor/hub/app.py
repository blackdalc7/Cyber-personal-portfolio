"""The Watchfloor hub: a read-mostly FastAPI service in front of the lake and the file outputs.

Routes (all JSON, under ``/api``):

* ``GET /health`` (no auth), ``GET /summary``, ``GET /events``, ``GET /events/{uid}``,
  ``GET /findings``, ``GET /incidents``, ``GET /incidents/{id}``, ``GET /process-tree``
* ``GET /scenarios``, ``GET /scenarios/{id}``, ``GET /scenarios/{id}/score``
* ``GET /coverage``, ``GET /coverage/{run_id}``, ``GET /exposure``, ``POST /exposure/what-if``
* ``GET /rules``, ``GET /evidence``, ``GET /analyst``
* ``GET /stream``: Server-Sent Events of new spine entries
* ``POST /ingest/{source}``: push telemetry (Tetragon, Windows event log, OCSF), token required

The read API needs ``Authorization: Bearer $WF_HUB_TOKEN`` when that variable is set;
``/stream`` also accepts ``?access_token=`` because browsers' EventSource cannot set
headers. Ingest always needs ``$WF_INGEST_TOKEN``, and is disabled when it is unset.
The hub never executes a response action: approvals stay in 02.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from .. import ocsf
from ..bus import EventBus
from ..config import Settings
from ..lake import LakeReader
from ..mappers import map_record
from ..scenarios import list_scenarios, load_scenario, score_stages
from . import artifacts, queries

logger = logging.getLogger("watchfloor.hub")

INGEST_SOURCES = ("tetragon", "winlog", "ocsf", "siem", "edr")


class WhatIf(BaseModel):
    """Body of ``POST /exposure/what-if``: CVE ids assumed patched."""
    patched: list[str] = Field(default_factory=list, max_length=200)


HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")


class IsolationRequest(BaseModel):
    """Body of ``POST /api/actions/isolation-request``: the host to isolate and why."""
    host: str = Field(min_length=1, max_length=253, pattern=HOST_RE.pattern)
    reason: str = Field(min_length=3, max_length=500)
    indicator_ip: str | None = Field(None, max_length=45)
    incident_id: str | None = Field(None, max_length=100)


# The dashboard loads only its own bundle; charts and graphs set inline styles, fonts come from Google Fonts.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'")

def create_app(settings: Settings, lake: LakeReader | None = None, bus: EventBus | None = None) -> FastAPI:
    """Build the FastAPI application. ``lake`` and ``bus`` are injectable for tests."""
    app = FastAPI(title="Watchfloor hub", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    lake = lake or LakeReader(settings.lake_dir)
    app.state.lake = lake
    app.state.bus = bus
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=["GET", "POST"],
                           allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        else:
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Frame-Options"] = "DENY"
        return resp

    def _check(token: str, header: str | None) -> bool:
        return bool(header) and hmac.compare_digest(header, f"Bearer {token}")

    def require_read(request: Request) -> None:
        if not settings.hub_token:
            return
        header = request.headers.get("Authorization")
        if not _check(settings.hub_token, header):
            raise HTTPException(401, "missing or invalid bearer token")

    def fresh_lake() -> LakeReader:
        lake.refresh()
        return lake

    read = [Depends(require_read)]

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "ocsf_version": ocsf.OCSF_VERSION, "live": bus is not None}

    @app.get("/api/summary", dependencies=read)
    def summary(since: int | None = None, scenario: str | None = None) -> dict[str, Any]:
        return queries.summary(fresh_lake(), since=since, scenario=scenario)

    @app.get("/api/events", dependencies=read)
    def list_events(class_uid: int | None = None, hostname: str | None = None, product: str | None = None,
                    scenario: str | None = None, since: int | None = None, until: int | None = None,
                    technique: str | None = None, q: str | None = Query(None, max_length=200),
                    limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        return queries.events(fresh_lake(), limit=limit, offset=offset, class_uid=class_uid, hostname=hostname,
                              product=product, scenario=scenario, since=since, until=until, technique=technique,
                              q=q)

    @app.get("/api/events/{uid}", dependencies=read)
    def get_event(uid: str) -> dict[str, Any]:
        doc = queries.event_raw(fresh_lake(), uid)
        if doc is None:
            raise HTTPException(404)
        return doc

    @app.get("/api/findings", dependencies=read)
    def list_findings(hostname: str | None = None, product: str | None = None, technique: str | None = None,
                      scenario: str | None = None, since: int | None = None, min_severity: int | None = None,
                      limit: int = 200) -> list[dict[str, Any]]:
        return queries.findings(fresh_lake(), limit=limit, hostname=hostname, product=product, technique=technique,
                                scenario=scenario, since=since, min_severity=min_severity)

    @app.get("/api/incidents", dependencies=read)
    def list_incidents(scenario: str | None = None) -> list[dict[str, Any]]:
        return queries.incidents(fresh_lake(), scenario=scenario)

    @app.get("/api/incidents/{incident_id}", dependencies=read)
    def get_incident(incident_id: str) -> dict[str, Any]:
        detail = queries.incident_detail(fresh_lake(), incident_id)
        if detail is None:
            raise HTTPException(404)
        evidence = [e for e in artifacts.json_dir(settings.evidence_dir, "*/manifest.json")
                    if e.get("incident_id") == incident_id]
        detail["evidence"] = evidence[:5]
        analyses = [a for a in artifacts.json_dir(settings.analyst_dir) if a.get("incident_id") == incident_id]
        detail["analyses"] = analyses[:5]
        return detail

    @app.get("/api/process-tree", dependencies=read)
    def get_tree(hostname: str, since: int | None = None, until: int | None = None) -> dict[str, Any]:
        return queries.process_tree(fresh_lake(), hostname, since, until)

    @app.get("/api/scenarios", dependencies=read)
    def scenarios() -> list[dict[str, Any]]:
        return [s.to_dict() for s in list_scenarios(settings.scenarios_dir)]

    def _scenario(scenario_id: str):
        path = Path(settings.scenarios_dir) / scenario_id
        if "/" in scenario_id or "\\" in scenario_id or ".." in scenario_id or not (path / "scenario.yml").is_file():
            raise HTTPException(404)
        return load_scenario(path)

    @app.get("/api/scenarios/{scenario_id}", dependencies=read)
    def scenario(scenario_id: str) -> dict[str, Any]:
        sc = _scenario(scenario_id)
        return {**sc.to_dict(), "events": sc.events()}

    @app.get("/api/scenarios/{scenario_id}/score", dependencies=read)
    def scenario_score(scenario_id: str, shift_ms: int = 0, source: str = "lake") -> dict[str, Any]:
        """Score the stages against the lake (``source=lake``) or the recorded dataset (``dataset``)."""
        sc = _scenario(scenario_id)
        evts = sc.events() if source == "dataset" else queries.scenario_events(fresh_lake(), scenario_id)
        for st in sc.stages:
            st.start += shift_ms
        return {"scenario": scenario_id, "source": source, "stages": score_stages(sc.stages, evts)}

    @app.get("/api/coverage", dependencies=read)
    def coverage() -> list[dict[str, Any]]:
        return artifacts.coverage_runs(settings.coverage_dir)

    @app.get("/api/coverage/{run_id}", dependencies=read)
    def coverage_run(run_id: str) -> dict[str, Any]:
        doc = artifacts.coverage_run(settings.coverage_dir, run_id)
        if doc is None:
            raise HTTPException(404)
        return doc

    @app.get("/api/exposure", dependencies=read)
    def exposure() -> dict[str, Any]:
        doc = artifacts.exposure(settings.exposure_file)
        if doc is None:
            raise HTTPException(404, "set WF_EXPOSURE_FILE to 04's findings.json")
        return doc

    @app.post("/api/exposure/what-if", dependencies=read)
    def exposure_what_if(body: WhatIf) -> dict[str, Any]:
        doc = artifacts.exposure(settings.exposure_file)
        if doc is None:
            raise HTTPException(404)
        return artifacts.what_if(doc, body.patched)

    @app.get("/api/rules", dependencies=read)
    def rules() -> dict[str, Any]:
        return artifacts.rules(settings.rules_index) or {"rules": [], "generated": None}

    @app.get("/api/evidence", dependencies=read)
    def evidence() -> list[dict[str, Any]]:
        return artifacts.json_dir(settings.evidence_dir, "*/manifest.json")

    @app.get("/api/analyst", dependencies=read)
    def analyst() -> list[dict[str, Any]]:
        return artifacts.json_dir(settings.analyst_dir)

    @app.get("/api/stream")
    async def stream(request: Request, access_token: str | None = None) -> StreamingResponse:
        if settings.hub_token:
            header = request.headers.get("Authorization") or (f"Bearer {access_token}" if access_token else None)
            if not _check(settings.hub_token, header):
                raise HTTPException(401)
        if bus is None:
            raise HTTPException(503, "live stream needs Redis (WF_REDIS_URL)")
        return StreamingResponse(_sse(bus, request), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    @app.post("/api/ingest/{source}")
    async def ingest(source: str, request: Request) -> dict[str, Any]:
        """Map raw records from one source to OCSF and publish them; unmappable records are counted as rejected."""
        if not settings.ingest_token:
            raise HTTPException(403, "ingest disabled: set WF_INGEST_TOKEN")
        if not _check(settings.ingest_token, request.headers.get("Authorization")):
            raise HTTPException(401)
        if source not in INGEST_SOURCES:
            raise HTTPException(404, f"source must be one of {', '.join(INGEST_SOURCES)}")
        if bus is None:
            raise HTTPException(503, "ingest needs Redis (WF_REDIS_URL)")
        body = await request.body()
        if len(body) > settings.max_ingest_bytes:
            raise HTTPException(413)
        records = parse_records(body)
        docs, rejected = [], 0
        for rec in records:
            try:
                doc = map_record(source, rec)
            except (ocsf.ContractError, KeyError, TypeError, ValueError):
                rejected += 1
                continue
            if doc is not None:
                docs.append(doc)
        accepted = bus.publish_many(docs, validate=False) if docs else 0
        return {"received": len(records), "accepted": accepted, "rejected": rejected,
                "skipped": len(records) - accepted - rejected}

    @app.post("/api/actions/isolation-request")
    def isolation_request(req: IsolationRequest, request: Request) -> dict[str, Any]:
        """Ask 02 to open an approval card for isolating a host. The hub never isolates anything itself:
        02 still needs a signed click from an approver in Slack or Discord before any remediation runs."""
        if not (settings.actions_enabled and settings.hub_token and settings.soar_url and settings.soar_webhook_secret):
            raise HTTPException(403, "actions disabled: set WF_ACTIONS_ENABLED, WF_HUB_TOKEN, WF_SOAR_URL and "
                                     "WF_SOAR_WEBHOOK_SECRET")
        require_read(request)
        where = f" for {req.incident_id}" if req.incident_id else ""
        alert = {
            "id": f"wf-isolate-{req.host}-{int(time.time())}",
            "title": f"Analyst-requested isolation of {req.host}",
            "severity": "high",
            "source": "watchfloor-analyst",
            "host": req.host,
            "source_ip": req.indicator_ip,
            "description": f"Requested from the Watchfloor console{where}. Reason: {req.reason}",
            "timestamp": int(time.time()),
        }
        body = json.dumps(alert, separators=(",", ":")).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(settings.soar_webhook_secret.encode(), f"{ts}.".encode() + body,
                                   hashlib.sha256).hexdigest()
        try:
            resp = httpx.post(f"{settings.soar_url}/alerts", content=body, timeout=10.0,
                              headers={"Content-Type": "application/json", "X-SOAR-Timestamp": ts,
                                       "X-SOAR-Signature": sig})
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"SOAR bot unreachable: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            raise HTTPException(502, f"SOAR bot answered {resp.status_code}")
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        logger.info("isolation approval requested for %s", req.host)
        return {"status": "approval_requested", "host": req.host, "soar": data}

    if settings.ui_dir and Path(settings.ui_dir).is_dir():
        ui_root = Path(settings.ui_dir).resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def ui(path: str) -> FileResponse:
            target = (ui_root / path).resolve()
            if path and target.is_file() and ui_root in target.parents:
                return FileResponse(target)
            return FileResponse(ui_root / "index.html")

    return app


def parse_records(body: bytes) -> list[dict[str, Any]]:
    """Accept a JSON array, a single JSON object, or NDJSON; non-object items are ignored."""
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        items = data if isinstance(data, list) else [data]
    except ValueError:
        items = []
        for line in text.splitlines():
            try:
                items.append(json.loads(line))
            except ValueError:
                continue
    return [i for i in items if isinstance(i, dict)]


def compact_event(doc: dict[str, Any]) -> dict[str, Any]:
    """The small projection of an event sent over SSE (the UI fetches details on demand)."""
    row = ocsf.flatten(doc)
    row.pop("raw", None)
    return row


async def _sse(bus: EventBus, request: Request) -> AsyncIterator[bytes]:
    last = "$"
    yield b"retry: 3000\n\n"
    while not await request.is_disconnected():
        entries = await asyncio.to_thread(bus.read_after, last, 200, 10_000)
        if not entries:
            yield b": keep-alive\n\n"
            continue
        for entry_id, doc in entries:
            last = entry_id
            payload = json.dumps(compact_event(doc), separators=(",", ":"), default=str)
            yield f"id: {entry_id}\nevent: ocsf\ndata: {payload}\n\n".encode()
