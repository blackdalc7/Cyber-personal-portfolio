"""End-to-end: real UDP socket -> server -> pipeline -> rotating NDJSON files."""

import asyncio
import json
import socket
from dataclasses import replace

from helpers import FIXTURES

from realtime_siem.ecs import validate
from realtime_siem.llm import OfflineSummarizer
from realtime_siem.pipeline import Pipeline
from realtime_siem.replay import iter_datagrams
from realtime_siem.server import SyslogServer


def read_ndjson(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


async def _run_replay(settings, fmt):
    pipeline = Pipeline(settings, OfflineSummarizer())
    server = SyslogServer(settings, pipeline)
    await server.start()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for dgram in iter_datagrams(FIXTURES / "auth.log", fmt, 2026):
            sock.sendto(dgram, ("127.0.0.1", server.bound_port))
            await asyncio.sleep(0)  # yield so the loop can read the socket buffer
        for _ in range(200):
            if pipeline.stats.received >= 138:
                break
            await asyncio.sleep(0.01)
        await server.drain()
    finally:
        sock.close()
        await server.stop()
        pipeline.close()
    return pipeline


def _assert_attack_detected(settings, pipeline):
    assert pipeline.stats.received == 138 and pipeline.stats.events == 138
    assert pipeline.stats.parse_failures == 0 and pipeline.stats.schema_errors == 0
    events = read_ndjson(settings.output_dir / "events.ndjson")
    alerts = read_ndjson(settings.output_dir / "alerts.ndjson")
    chains = read_ndjson(settings.output_dir / "chains.ndjson")
    assert len(events) == 138
    for doc in events + alerts + chains:
        validate(doc)
    rules = {a["rule"]["id"] for a in alerts}
    assert rules == {"SIEM-AUTH-001", "SIEM-AUTH-002", "SIEM-AUTH-003", "SIEM-PRIV-001"}
    critical = [c for c in chains if c["siem"]["chain"]["attack_stage"] == "post_compromise"]
    assert critical and critical[-1]["source"]["ip"] == "203.0.113.66"
    assert critical[-1]["siem"]["chain"]["verdict"] == "True Positive"


def test_udp_end_to_end_rfc5424(settings):
    settings = replace(settings, bind_host="127.0.0.1", bind_port=0)
    pipeline = asyncio.run(_run_replay(settings, "rfc5424"))
    _assert_attack_detected(settings, pipeline)
    assert pipeline.stats.by_format == {"rfc5424": 138}


def test_udp_end_to_end_rfc3164(settings):
    settings = replace(settings, bind_host="127.0.0.1", bind_port=0, default_timezone="UTC")
    pipeline = asyncio.run(_run_replay(settings, "rfc3164"))
    _assert_attack_detected(settings, pipeline)


def test_allow_list_rejects_unknown_sources(settings):
    import ipaddress
    settings = replace(settings, bind_host="127.0.0.1", bind_port=0,
                       allowed_sources=(ipaddress.ip_network("10.0.0.0/8"),))

    async def go():
        pipeline = Pipeline(settings, OfflineSummarizer())
        server = SyslogServer(settings, pipeline)
        await server.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"<38>Oct 26 08:01:30 web01 sshd[1]: hi", ("127.0.0.1", server.bound_port))
            for _ in range(100):
                if pipeline.stats.received:
                    break
                await asyncio.sleep(0.01)
        await server.stop()
        pipeline.close()
        return pipeline

    pipeline = asyncio.run(go())
    assert pipeline.stats.received == 1 and pipeline.stats.rejected_source == 1 and pipeline.stats.events == 0


def test_queue_full_drops_and_counts(settings):
    settings = replace(settings, queue_max=1)
    pipeline = Pipeline(settings, OfflineSummarizer())

    async def go():
        server = SyslogServer(settings, pipeline)  # not started: nothing drains the queue
        for _ in range(5):
            server.on_datagram(b"<38>Oct 26 08:01:30 web01 sshd[1]: hi", ("127.0.0.1", 5000))
        return server

    asyncio.run(go())
    pipeline.close()
    assert pipeline.stats.received == 5 and pipeline.stats.dropped_queue_full == 4


def test_poison_datagram_does_not_kill_worker(settings, monkeypatch):
    settings = replace(settings, bind_host="127.0.0.1", bind_port=0)
    pipeline = Pipeline(settings, OfflineSummarizer())
    original = pipeline.ingest
    calls = {"n": 0}

    def flaky(data, peer, received_at=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return original(data, peer, received_at)

    monkeypatch.setattr(pipeline, "ingest", flaky)

    async def go():
        server = SyslogServer(settings, pipeline)
        await server.start()
        server.on_datagram(b"<38>Oct 26 08:01:30 web01 sshd[1]: one", ("127.0.0.1", 1))
        server.on_datagram(b"<38>Oct 26 08:01:31 web01 sshd[1]: two", ("127.0.0.1", 1))
        await server.drain()
        await server.stop()

    asyncio.run(go())
    pipeline.close()
    assert pipeline.stats.events == 1
