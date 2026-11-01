# detection-rules: Sigma rules over the Watchfloor lake. Runs as an unprivileged user with a read-only lake mount.
FROM python:3.15-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src ./src
COPY rules ./rules
COPY samples ./samples
# The rules are tested at build time: an image with a failing rule never ships.
RUN PYTHONPATH=src python -m detection_rules build
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /state && chown app:app /state
USER app
ENV PYTHONPATH=/app/src RULES_STATE_FILE=/state/state.json
ENTRYPOINT ["python", "-m", "detection_rules"]
CMD ["run", "--watch", "--interval", "60"]
