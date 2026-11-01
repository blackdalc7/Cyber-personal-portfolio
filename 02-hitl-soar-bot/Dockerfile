# syntax=docker/dockerfile:1.7
# ---- build stage: compile wheels so the runtime image carries no build tooling ----
FROM python:3.15-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

# ---- runtime stage ----
FROM python:3.15-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src SOAR_DATA_DIR=/data LISTEN_HOST=0.0.0.0 LISTEN_PORT=8080
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels /wheels/* && rm -rf /wheels \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin soar \
 && mkdir -p /data && chown soar:soar /data
COPY src/ ./src/
COPY scripts/ ./scripts/
USER soar
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "soar_bot"]
