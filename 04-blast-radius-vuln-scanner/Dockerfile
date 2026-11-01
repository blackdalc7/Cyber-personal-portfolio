# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home scanner
COPY --from=build /install /usr/local
WORKDIR /app
COPY src/ src/
COPY scripts/ scripts/
COPY examples/ examples/
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp/mpl \
    VULN_CACHE_PATH=/data/cache.sqlite
RUN mkdir -p /data /out && chown scanner:scanner /data /out
USER scanner
# Unprivileged: scanner.sh falls back to a TCP connect scan (-sT). Grant NET_RAW and run as root only if
# you need SYN scans.
ENTRYPOINT ["python", "-m", "vuln_scanner"]
CMD ["analyse", "examples/lab_scan.xml", "--inventory", "examples/inventory.yml", "--feeds-dir", "examples/feeds", \
     "--sarif", "/out/results.sarif", "--report", "/out/report.md", "--graph", "/out/blast_radius.png"]
