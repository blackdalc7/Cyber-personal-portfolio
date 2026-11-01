"""Velociraptor server API (gRPC) for one job: find the client, collect, wait, read the results.

Every value that comes from a request (host name, client id, flow id, artifact names) reaches VQL as a query
*environment variable*, never by string formatting, so a hostile host name cannot change the query.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Protocol

import yaml

log = logging.getLogger("evidence_timeline.velociraptor")

FIND_CLIENT = ("SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn, last_seen_at "
               "FROM clients(search='host:' + Host)")
COLLECT = ("SELECT collect_client(client_id=ClientId, artifacts=split(string=Artifacts, sep=','), "
           "timeout=int(int=Timeout)) AS flow FROM scope()")
FLOW_STATE = "SELECT state, status, artifacts_with_results FROM flows(client_id=ClientId, flow_id=FlowId)"
RESULTS = "SELECT * FROM source(client_id=ClientId, flow_id=FlowId, artifact=Artifact)"


class VelociraptorError(RuntimeError):
    """The server or the client did not do what was asked."""


class QueryFn(Protocol):
    def __call__(self, vql: str, env: dict[str, str], max_rows: int = ...) -> list[dict[str, Any]]: ...


def grpc_query(api_config: Path, timeout_s: int = 600) -> QueryFn:
    """A query function bound to the server described by an ``api_client`` config file."""
    import grpc
    from pyvelociraptor import api_pb2, api_pb2_grpc

    cfg = yaml.safe_load(Path(api_config).read_text(encoding="utf-8"))
    creds = grpc.ssl_channel_credentials(root_certificates=cfg["ca_certificate"].encode(),
                                         private_key=cfg["client_private_key"].encode(),
                                         certificate_chain=cfg["client_cert"].encode())
    options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
    target = cfg["api_connection_string"]

    def query(vql: str, env: dict[str, str], max_rows: int = 10_000) -> list[dict[str, Any]]:
        req = api_pb2.VQLCollectorArgs(max_wait=1, max_row=max_rows, timeout=timeout_s,
                                       Query=[api_pb2.VQLRequest(Name="evidence", VQL=vql)],
                                       env=[api_pb2.VQLEnv(key=k, value=v) for k, v in env.items()])
        rows: list[dict[str, Any]] = []
        with grpc.secure_channel(target, creds, options) as channel:
            for resp in api_pb2_grpc.APIStub(channel).Query(req):
                if resp.log:
                    log.debug("vql: %s", resp.log.strip())
                if resp.Response:
                    rows.extend(json.loads(resp.Response))
                if len(rows) >= max_rows:
                    break
        return rows[:max_rows]

    return query


class Velociraptor:
    def __init__(self, query: QueryFn, *, poll_s: float = 10.0, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time) -> None:
        self._q = query
        self._poll = poll_s
        self._sleep = sleep
        self._clock = clock

    def find_client(self, host: str) -> str:
        rows = self._q(FIND_CLIENT, {"Host": host})
        h = host.lower()
        exact = [r for r in rows if str(r.get("hostname") or "").lower() == h
                 or str(r.get("fqdn") or "").lower().split(".")[0] == h]
        if not exact:
            raise VelociraptorError(f"no Velociraptor client enrolled for host {host!r}")
        exact.sort(key=lambda r: r.get("last_seen_at") or 0, reverse=True)
        return str(exact[0]["client_id"])

    def collect(self, client_id: str, artifacts: list[str], timeout_s: int) -> str:
        rows = self._q(COLLECT, {"ClientId": client_id, "Artifacts": ",".join(artifacts), "Timeout": str(timeout_s)})
        flow = (rows[0].get("flow") if rows else None) or {}
        flow_id = flow.get("flow_id") if isinstance(flow, dict) else None
        if not flow_id:
            raise VelociraptorError(f"collection was not scheduled on {client_id}: {rows!r}"[:300])
        return str(flow_id)

    def wait(self, client_id: str, flow_id: str, timeout_s: int) -> list[str]:
        """Block until the flow finishes; return the artifacts that produced results."""
        deadline = self._clock() + timeout_s
        while True:
            rows = self._q(FLOW_STATE, {"ClientId": client_id, "FlowId": flow_id})
            state = str((rows[0] if rows else {}).get("state") or "UNKNOWN").upper()
            if state == "FINISHED":
                return list((rows[0] or {}).get("artifacts_with_results") or [])
            if state == "ERROR":
                raise VelociraptorError(f"flow {flow_id} failed: {(rows[0] or {}).get('status')}")
            if self._clock() >= deadline:
                raise VelociraptorError(f"flow {flow_id} still {state} after {timeout_s}s")
            self._sleep(self._poll)

    def results(self, client_id: str, flow_id: str, artifact: str, max_rows: int) -> list[dict[str, Any]]:
        return self._q(RESULTS, {"ClientId": client_id, "FlowId": flow_id, "Artifact": artifact}, max_rows=max_rows)

    def collect_all(self, host: str, artifacts: list[str], timeout_s: int, max_rows: int
                    ) -> Iterator[tuple[str, list[dict[str, Any]], dict[str, str]]]:
        """Yield ``(artifact, rows, meta)`` for every artifact that returned rows."""
        client_id = self.find_client(host)
        flow_id = self.collect(client_id, artifacts, timeout_s)
        log.info("collecting %s from %s (%s), flow %s", ",".join(artifacts), host, client_id, flow_id)
        with_results = set(self.wait(client_id, flow_id, timeout_s))
        meta = {"client_id": client_id, "flow_id": flow_id}
        for art in artifacts:
            if any(w == art or w.startswith(art + "/") for w in with_results):
                yield art, self.results(client_id, flow_id, art, max_rows), meta
