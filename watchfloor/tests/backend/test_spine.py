import json

import fakeredis
import httpx
import pytest

from helpers import PORTFOLIO, auth_event, finding
from watchfloor.adapters import AdapterState, NdjsonTailer, QueueFileWatcher, SoarPoller
from watchfloor.bus import EventBus
from watchfloor.ingest import GROUP, IngestService
from watchfloor.lake import LakeReader, LakeWriter

T = 1793005200000


@pytest.fixture
def bus():
    return EventBus(fakeredis.FakeRedis(decode_responses=True))


def test_publish_validates_and_dead_letters(bus):
    assert bus.publish(auth_event(T, True))
    bad = auth_event(T, True)
    del bad["user"]
    assert bus.publish(bad) is None
    assert bus.r.xlen("wf:events") == 1
    dl = bus.dead_letters()
    assert len(dl) == 1 and "user" in dl[0]["reason"]


def test_publish_many_and_read(bus):
    bad = auth_event(T, True)
    bad["type_uid"] = 0
    assert bus.publish_many([auth_event(T, True), bad, auth_event(T + 1, False)]) == 2
    entries = bus.read_after("0", block_ms=10)
    assert [e["time"] for _, e in entries] == [T, T + 1]


def test_group_read_ack_and_bad_entry(bus):
    bus.ensure_group("g")
    bus.ensure_group("g")  # idempotent
    bus.publish(auth_event(T, True))
    bus.r.xadd("wf:events", {"e": "{not json"})
    bus.r.xadd("wf:events", {"other": "x"})
    got = bus.read_group("g", "c1", block_ms=10)
    assert len(got) == 1
    bus.ack("g", [got[0][0]])
    assert bus.r.xpending("wf:events", "g")["pending"] == 2


def test_lake_round_trip_and_compaction(tmp_path):
    w = LakeWriter(tmp_path, flush_rows=2)
    r = LakeReader(tmp_path)
    assert r.scalar("SELECT count(*) FROM events") == 0
    w.add(auth_event(1793005200000, True))
    assert w.pending() == 1
    w.add(auth_event(1793005201000, False))  # reaches flush_rows -> flushed
    assert w.pending() == 0
    w.add_many([finding(1793005202000, ["T1078"]), auth_event(1793005203000, True)])
    w.flush()
    r.refresh()
    rows = r.query("SELECT class_uid, count(*) AS n FROM events GROUP BY 1 ORDER BY 1")
    assert rows == [{"class_uid": 2004, "n": 1}, {"class_uid": 3002, "n": 3}]
    assert r.scalar("SELECT time FROM events WHERE class_uid = 2004") == 1793005202000
    assert w.compact(now=1793005200) == 0  # hour not closed yet
    assert w.compact(now=1793020000) == 1
    r.refresh()
    assert r.scalar("SELECT count(*) FROM events") == 4
    r.close()


def test_ingest_service_flushes_and_acks(bus, tmp_path):
    w = LakeWriter(tmp_path)
    t = [0.0]
    svc = IngestService(bus, w, flush_interval_s=5, compact_every_s=100, clock=lambda: t[0])
    bus.publish_many([auth_event(1793005200000 + i, True) for i in range(3)])
    assert svc.step(block_ms=10) == 3
    assert w.pending() == 3
    t[0] = 6
    svc.step(block_ms=10)
    assert w.pending() == 0 and w.rows_written == 3
    assert bus.r.xpending("wf:events", GROUP)["pending"] == 0
    t[0] = 200
    svc.step(block_ms=10)
    svc.stop()
    svc.run()  # returns immediately once stopped, after a final flush


def test_ndjson_tailer_offsets_partial_lines_and_rotation(bus, tmp_path):
    path = tmp_path / "alerts.ndjson"
    src = {"@timestamp": "2026-10-26T11:00:00Z", "event": {"id": "a", "kind": "event",
                                                         "category": ["authentication"], "outcome": "success"},
           "host": {"hostname": "web01"}, "user": {"name": "x"}}
    path.write_text(json.dumps(src) + "\n" + "{bad json}\n" + json.dumps(src)[:20])
    state = AdapterState(tmp_path / "state.json")
    tail = NdjsonTailer(path, "siem", bus, state)
    assert tail.poll() == 1
    assert tail.poll() == 0
    with path.open("a") as fh:
        fh.write(json.dumps(src)[20:] + "\n")
    assert tail.poll() == 1
    path.unlink()
    assert tail.poll() == 0
    path.write_text(json.dumps(src) + "\n")  # new file (rotation)
    assert NdjsonTailer(path, "siem", bus, AdapterState(tmp_path / "state.json")).poll() == 1


def test_queue_watcher_republishes_on_change(bus, tmp_path):
    q = tmp_path / "queue.json"
    q.write_text((PORTFOLIO / "06-alert-clustering-fp-reducer/examples/output/queue.json").read_text())
    state = AdapterState(tmp_path / "s.json")
    w = QueueFileWatcher(q, bus, state)
    n = w.poll()
    assert n > 10
    assert w.poll() == 0
    assert QueueFileWatcher(tmp_path / "missing.json", bus, state).poll() == 0


def test_soar_poller_publishes_state_changes(bus, tmp_path):
    rows = [{"id": "INC-1", "title": "t", "severity": "high", "status": "awaiting_approval", "host": "web01",
             "detected_at": 100.0}]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/incidents"
        return httpx.Response(200, json=rows)

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://soar")
    p = SoarPoller("http://soar", "tok", bus, AdapterState(tmp_path / "s.json"), client=client)
    assert p.poll() == 1
    assert p.poll() == 0
    rows[0]["status"] = "remediated"
    assert p.poll() == 1


def test_adapter_state_survives_corrupt_file(tmp_path):
    f = tmp_path / "s.json"
    f.write_text("{oops")
    s = AdapterState(f)
    assert s.get("x", 1) == 1
    s.set("x", 2)
    assert AdapterState(f).get("x") == 2
