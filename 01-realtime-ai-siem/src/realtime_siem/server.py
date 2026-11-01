"""Asyncio UDP syslog receiver.

Concurrency model
-----------------
``datagram_received`` runs on the event loop and does almost nothing: an
allow-list check and a non-blocking ``put_nowait`` onto a bounded queue. If the
queue is full the datagram is counted and dropped (UDP has no back-pressure, so
shedding load visibly is better than unbounded memory growth).

A single worker coroutine drains the queue and runs the synchronous pipeline.
Chain summaries (LLM calls, seconds of latency) are pushed to a thread via
``asyncio.to_thread`` behind a semaphore, so a slow API never stalls ingestion.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone

from .config import ConfigError, Settings
from .correlation import AlertChain
from .llm import build_summarizer
from .pipeline import Pipeline
from .sinks import configure_app_logging

logger = logging.getLogger("realtime_siem.server")

MAX_DATAGRAM = 65_535


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol that forwards each packet to the server."""
    def __init__(self, server: SyslogServer) -> None:
        self.server = server

    def datagram_received(self, data: bytes, addr) -> None:
        """Hand one received datagram to the owning server."""
        self.server.on_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        """Log socket-level errors (for example ICMP port unreachable) without stopping."""
        logger.warning("UDP socket error: %s", exc)


class SyslogServer:
    """UDP syslog listener with a bounded queue and a single processing worker.

    The event-loop callback only enqueues, so a slow LLM or disk can never block
    receiving. When the queue is full new datagrams are dropped and counted.
    Chain summaries run in worker threads, limited by ``llm_concurrency``.
    """
    def __init__(self, settings: Settings, pipeline: Pipeline, llm_concurrency: int = 2) -> None:
        self.s = settings
        self.pipeline = pipeline
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int], datetime]] = asyncio.Queue(settings.queue_max)
        self._transport: asyncio.DatagramTransport | None = None
        self._worker: asyncio.Task | None = None
        self._stats_task: asyncio.Task | None = None
        self._llm_sem = asyncio.Semaphore(llm_concurrency)
        self._llm_tasks: set[asyncio.Task] = set()
        self.bound_port: int | None = None

    # -- event-loop callbacks ------------------------------------------------
    def on_datagram(self, data: bytes, addr) -> None:
        """Accept or reject one datagram: check the source allow-list, then enqueue it."""
        stats = self.pipeline.stats
        stats.received += 1
        peer = (addr[0], addr[1])
        if not self.s.source_allowed(peer[0]):
            stats.rejected_source += 1
            return
        try:
            self.queue.put_nowait((data[:MAX_DATAGRAM], peer, datetime.now(timezone.utc)))
        except asyncio.QueueFull:
            stats.dropped_queue_full += 1

    # -- lifecycle -----------------------------------------------------------
    async def start(self) -> None:
        """Bind the UDP socket and start the worker and stats tasks."""
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self), local_addr=(self.s.bind_host, self.s.bind_port))
        self.bound_port = self._transport.get_extra_info("sockname")[1]
        self._worker = asyncio.create_task(self._work(), name="siem-worker")
        if self.s.stats_interval_s:
            self._stats_task = asyncio.create_task(self._report_stats(), name="siem-stats")
        logger.info("Listening for syslog on udp://%s:%s (LLM provider: %s)",
                    self.s.bind_host, self.bound_port, self.s.llm_provider)

    async def stop(self, drain_timeout: float = 10.0) -> None:
        """Stop receiving, drain the queue and pending summaries, then flush the sinks."""
        if self._transport:
            self._transport.close()
        try:
            await asyncio.wait_for(self.queue.join(), timeout=drain_timeout)
        except asyncio.TimeoutError:
            logger.warning("Shutdown: %d datagrams left unprocessed", self.queue.qsize())
        if self._llm_tasks:
            await asyncio.wait(self._llm_tasks, timeout=drain_timeout)
        for task in (self._worker, self._stats_task):
            if task:
                task.cancel()
        self.pipeline.flush()
        logger.info("Stopped. Final stats: %s", json.dumps(self.pipeline.stats.as_dict()))

    async def drain(self) -> None:
        """Wait until every queued datagram and pending summary is processed (used by tests)."""
        await self.queue.join()
        while self._llm_tasks:
            await asyncio.wait(set(self._llm_tasks))

    # -- workers -------------------------------------------------------------
    async def _work(self) -> None:
        while True:
            data, peer, received_at = await self.queue.get()
            try:
                for chain in self.pipeline.ingest(data, peer, received_at):
                    self._schedule_summary(chain)
            except Exception:  # a single poison datagram must never kill the listener
                logger.exception("Unhandled error processing datagram from %s", peer[0])
            finally:
                self.queue.task_done()

    def _schedule_summary(self, chain: AlertChain) -> None:
        # Snapshot on the loop thread: the worker keeps appending to the live chain.
        snap = self.pipeline.snapshot(chain)

        async def run() -> None:
            """Summarise the snapshot in a thread, bounded by the LLM semaphore."""
            async with self._llm_sem:
                try:
                    await asyncio.to_thread(self.pipeline.summarize_snapshot, snap)
                except Exception:
                    logger.exception("Chain summarisation failed for %s", snap.chain_id)

        task = asyncio.create_task(run(), name=f"siem-chain-{chain.id}")
        self._llm_tasks.add(task)
        task.add_done_callback(self._llm_tasks.discard)

    async def _report_stats(self) -> None:
        while True:
            await asyncio.sleep(self.s.stats_interval_s)
            self.pipeline.flush()
            logger.info("stats %s queue=%d", json.dumps(self.pipeline.stats.as_dict()), self.queue.qsize())


async def serve(settings: Settings) -> None:
    """Run the SIEM until SIGINT or SIGTERM, then shut down gracefully."""
    pipeline = Pipeline(settings, build_summarizer(settings))
    server = SyslogServer(settings, pipeline)
    await server.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows event loops lack add_signal_handler
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))
    await stop.wait()
    await server.stop()
    pipeline.close()


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (2 on a configuration error)."""
    ap = argparse.ArgumentParser(prog="realtime-siem", description="Real-time UDP syslog SIEM with ECS output.")
    ap.add_argument("--env-file", help="Path to a .env file (default: ./.env if present)")
    ap.add_argument("--host", help="Override SYSLOG_BIND_HOST")
    ap.add_argument("--port", type=int, help="Override SYSLOG_BIND_PORT")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        settings = Settings.from_env(dotenv_path=args.env_file)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    overrides = {}
    if args.host:
        overrides["bind_host"] = args.host
    if args.port is not None:
        overrides["bind_port"] = args.port
    if overrides:
        from dataclasses import replace
        settings = replace(settings, **overrides)

    configure_app_logging(settings.output_dir, settings.rotate_max_bytes, settings.rotate_backup_count,
                          logging.DEBUG if args.verbose else logging.INFO)
    try:
        asyncio.run(serve(settings))
    except OSError as exc:
        logger.error("Could not bind udp://%s:%s: %s", settings.bind_host, settings.bind_port, exc)
        return 1
    return 0
