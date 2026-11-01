FROM python:3.15-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
RUN useradd --system --uid 10001 siem && mkdir -p /data && chown siem /data
USER siem
ENV PYTHONPATH=/app/src SIEM_OUTPUT_DIR=/data SYSLOG_BIND_PORT=5514
EXPOSE 5514/udp
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "realtime_siem"]
