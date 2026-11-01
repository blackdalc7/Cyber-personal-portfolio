# ai-analyst: investigates new Watchfloor incidents with read-only MCP tools and writes cited transcripts.
FROM python:3.15-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src ./src
COPY examples/cmdb_seed.yml ./examples/cmdb_seed.yml
COPY evals ./evals
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /analyst && chown app:app /analyst
USER app
# If /cmdb/cmdb.sqlite is missing, the CMDB is built from ANALYST_CMDB_SEED into /tmp at start-up.
ENV PYTHONPATH=/app/src ANALYST_LAKE_DIR=/lake ANALYST_OUT_DIR=/analyst ANALYST_CMDB_PATH=/cmdb/cmdb.sqlite \
    ANALYST_CMDB_SEED=/app/examples/cmdb_seed.yml
VOLUME ["/analyst"]
ENTRYPOINT ["python", "-m", "ai_analyst"]
CMD ["watch", "--interval", "60"]
