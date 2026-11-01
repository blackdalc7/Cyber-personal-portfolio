# syntax=docker/dockerfile:1.7
# One image runs every Watchfloor role (hub, ingest, adapters, replay); the compose file picks the command.
# Build from the repository root so the shared design system is in the context:
#   docker build -f deploy/watchfloor/Dockerfile .

# ---- UI build: the live dashboard the hub serves at / ----
FROM node:22-alpine AS ui
WORKDIR /src
COPY packages/aegis-ui/ packages/aegis-ui/
RUN cd packages/aegis-ui && npm ci --no-audit --no-fund --omit=dev
COPY watchfloor/frontend/package.json watchfloor/frontend/package-lock.json watchfloor/frontend/
RUN cd watchfloor/frontend && npm ci --no-audit --no-fund
COPY watchfloor/frontend/ watchfloor/frontend/
RUN cd watchfloor/frontend && npm run build

# ---- Python wheels, so the runtime image carries no build tooling ----
FROM python:3.12-slim AS wheels
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY watchfloor/backend/requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

# ---- runtime ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/app/src \
    WF_LAKE_DIR=/lake WF_UI_DIR=/app/ui/dist WF_SCENARIOS_DIR=/app/datasets/scenarios
WORKDIR /app
COPY --from=wheels /wheels /wheels
RUN pip install --no-index --find-links=/wheels /wheels/* && rm -rf /wheels \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin wf \
 && mkdir -p /lake && chown wf:wf /lake
COPY watchfloor/backend/src/ ./src/
COPY watchfloor/datasets/ ./datasets/
COPY --from=ui /src/watchfloor/frontend/dist ./ui/dist
USER wf
EXPOSE 8000
VOLUME ["/lake"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "watchfloor"]
CMD ["hub", "--host", "0.0.0.0", "--port", "8000"]
