# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN useradd --uid 10001 --create-home triage
COPY --from=build /install /usr/local
WORKDIR /app
COPY src/ src/
COPY config/ config/
COPY examples/cmdb_seed.yml examples/cmdb_seed.yml
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TRIAGE_DB_PATH=/data/cmdb.sqlite
RUN mkdir -p /data /out && chown triage:triage /data /out
USER triage
# ANTHROPIC_API_KEY is passed at run time (docker run --env-file .env); without it the image runs offline.
ENTRYPOINT ["python", "-m", "alert_triage"]
CMD ["--help"]
