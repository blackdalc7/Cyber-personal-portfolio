# evidence-timeline: the signed /collect API n8n calls after a human approves containment in 02.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src ./src
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /evidence && chown app:app /evidence
USER app
ENV PYTHONPATH=/app/src EVIDENCE_OUT_DIR=/evidence EVIDENCE_LISTEN_HOST=0.0.0.0
EXPOSE 8090
VOLUME ["/evidence"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "evidence_timeline"]
CMD ["serve"]
