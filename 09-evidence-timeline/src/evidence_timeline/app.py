"""HTTP API. Only signed requests start or read collections; n8n calls it after a human approves in 02.

    POST /collect           {"incident_id", "host", "around_ms"?, "requested_by"?, "decided_by"?, "reason"?,
                             "force"?}  -> 202 {"job": {...}, "created": bool}
    GET  /jobs/{incident}   -> job status (signed: the body is empty, the timestamp is still signed)
    GET  /healthz
"""

from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from .config import Settings
from .jobs import HOST, INCIDENT_ID, CollectRequest, JobStore
from .signing import Verifier

MAX_BODY = 16 * 1024


class CollectBody(BaseModel):
    incident_id: str = Field(pattern=INCIDENT_ID.pattern)
    host: str = Field(pattern=HOST.pattern)
    around_ms: int | None = Field(default=None, ge=0)
    requested_by: str | None = Field(default=None, max_length=100)
    decided_by: str | None = Field(default=None, max_length=100)
    reason: str | None = Field(default=None, max_length=500)
    force: bool = False


def create_app(settings: Settings, store: JobStore | None = None, verifier: Verifier | None = None) -> FastAPI:
    app = FastAPI(title="Evidence timeline", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None)
    jobs = store or JobStore(settings)
    verify = verifier or Verifier(settings.shared_secret)

    async def signed_body(request: Request) -> bytes:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise HTTPException(413)
        if not verify.verify(body, request.headers.get("X-SOAR-Timestamp"), request.headers.get("X-SOAR-Signature")):
            raise HTTPException(401, "bad or missing signature")
        return body

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    @app.post("/collect", status_code=202)
    async def collect(request: Request) -> JSONResponse:
        body = await signed_body(request)
        try:
            req = CollectBody.model_validate(json.loads(body))
        except (ValueError, ValidationError) as exc:
            raise HTTPException(422, "invalid collect request") from exc
        job, created = jobs.submit(CollectRequest(
            incident_id=req.incident_id, host=req.host, around_ms=req.around_ms, requested_by=req.requested_by,
            decided_by=req.decided_by, reason=req.reason), force=req.force)
        return JSONResponse({"job": job.as_dict(), "created": created}, status_code=202 if created else 200)

    @app.get("/jobs/{incident_id}")
    async def job(incident_id: str, request: Request) -> dict:
        await signed_body(request)
        found = jobs.get(incident_id)
        if found is None:
            raise HTTPException(404)
        return found.as_dict()

    app.state.jobs = jobs
    return app
