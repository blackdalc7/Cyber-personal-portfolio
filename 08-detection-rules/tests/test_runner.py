from __future__ import annotations

import json

import duckdb
import httpx
import pytest

from detection_rules.findings import finding_uid, to_finding
from detection_rules.lake import memory_lake, open_lake
from detection_rules.runner import HubSink, PrintSink, State, run_cycle, watch
from detection_rules.testing import envelope

NOW = 1_790_845_300_000


def shadow_read(t: int, i: int, path: str = "/usr/bin/cat") -> dict:
    return envelope({"class_uid": 1001, "activity_id": 2, "file": {"path": "/etc/shadow", "name": "shadow"},
                     "device": {"hostname": "lab-k8s"},
                     "actor": {"process": {"name": path.rsplit("/", 1)[-1], "cmd_line": f"{path} /etc/shadow",
                                           "file": {"path": path}}}}, uid=f"ev{i}", time=t)


class ListSink:
    def __init__(self):
        self.batches = []

    def send(self, findings):
        self.batches.append(findings)


def shadow_rule(rules):
    return [r for r in rules if r.stem == "file_access_lnx_shadow_read"]


def test_finding_document(rules):
    rule = shadow_rule(rules)[0]
    hit = {"uid": "ev1", "time": NOW - 5000, "hostname": "lab-k8s", "process_name": "cat",
           "cmd_line": "/usr/bin/cat /etc/shadow", "target_file": "/etc/shadow", "process_path": "/usr/bin/cat"}
    f = to_finding(rule, hit, now_ms=NOW)
    assert f["class_uid"] == 2004 and f["type_uid"] == 200401 and f["severity_id"] == 4 and f["time"] == NOW
    assert f["metadata"]["uid"] == f["finding_info"]["uid"] == finding_uid(rule.id, "ev1")
    assert f["finding_info"]["attacks"] == [{"technique": {"uid": "T1003.008"}, "version": "v17",
                                             "tactic": {"name": "credential-access"}}]
    assert f["finding_info"]["related_events"] == [{"uid": "ev1"}] and f["device"] == {"hostname": "lab-k8s"}
    assert f["unmapped"]["matched"]["target_file"] == "/etc/shadow" and f["unmapped"]["event_time"] == NOW - 5000
    assert f["actor"]["process"]["name"] == "cat"
    bare = to_finding(rule, {"uid": "ev2", "time": 1}, now_ms=NOW)
    assert "device" not in bare and "actor" not in bare


def test_contract_with_watchfloor(rules):
    """The finding validates against Watchfloor's OCSF schema when it is next door."""
    pytest.importorskip("jsonschema")
    import sys
    from pathlib import Path
    src = Path(__file__).resolve().parents[2] / "watchfloor" / "backend" / "src"
    if not src.is_dir():
        pytest.skip("watchfloor not checked out next to this project")
    sys.path.insert(0, str(src))
    from watchfloor import ocsf
    rule = shadow_rule(rules)[0]
    ocsf.validate(to_finding(rule, {"uid": "ev1", "time": 1, "hostname": "h", "process_name": "cat",
                                    "cmd_line": "cat"}, now_ms=NOW))
    from conftest import SAMPLES

    from detection_rules.testing import load_samples
    for r in rules:
        for kind in ("match", "nomatch"):
            for s in load_samples(SAMPLES, r)[kind]:
                ocsf.validate(s["event"])


def test_cycle_dedupes_across_the_overlap(rules):
    rule = shadow_rule(rules)
    con = memory_lake([shadow_read(NOW - 30_000, 1), shadow_read(NOW - 20_000, 2, "/usr/sbin/unix_chkpwd"),
                       shadow_read(NOW - 7_200_000, 3)])
    sink, state = ListSink(), State()
    r = run_cycle(rule, con, sink, state, now_ms=NOW, lookback_s=3600, overlap_s=120)
    assert (r.hits, r.sent, r.since) == (1, 1, NOW - 3_600_000)  # ev3 is older than the lookback
    assert state.watermark == NOW and len(state.emitted) == 1
    r2 = run_cycle(rule, con, sink, state, now_ms=NOW + 60_000, lookback_s=3600, overlap_s=120)
    assert r2.since == NOW - 120_000 and r2.hits == 1 and r2.sent == 0 and len(sink.batches) == 1
    run_cycle(rule, con, sink, state, now_ms=NOW + 3_600_000, lookback_s=3600, overlap_s=120)
    assert state.emitted == {}  # pruned once it can no longer be re-read


def test_failed_send_does_not_advance(rules):
    class Boom:
        def send(self, findings):
            raise httpx.ConnectError("down")

    state = State()
    con = memory_lake([shadow_read(NOW - 1000, 1)])
    with pytest.raises(httpx.ConnectError):
        run_cycle(shadow_rule(rules), con, Boom(), state, now_ms=NOW, lookback_s=60, overlap_s=10)
    assert state.watermark is None and state.emitted == {}


def test_broken_rule_is_reported_not_fatal(rules):
    from dataclasses import replace
    bad = replace(shadow_rule(rules)[0], sql="SELECT nope FROM ocsf_flat WHERE time >= ? AND time < ?")
    r = run_cycle([bad, *shadow_rule(rules)], memory_lake([shadow_read(NOW - 1, 1)]), ListSink(), State(),
                  now_ms=NOW, lookback_s=60, overlap_s=0)
    assert len(r.errors) == 1 and r.sent == 1


def test_state_roundtrip(tmp_path, caplog):
    p = tmp_path / "s" / "state.json"
    assert State.load(p).watermark is None
    State(watermark=5, emitted={"a": 1}).save(p)
    assert State.load(p) == State(watermark=5, emitted={"a": 1})
    p.write_text("{")
    assert State.load(p).watermark is None and "unreadable" in caplog.text


def test_hub_sink():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"received": 2, "accepted": 2, "rejected": 0})

    sink = HubSink("http://hub.test/", "tok", client=httpx.Client(transport=httpx.MockTransport(handler)))
    sink.send([{"a": 1}, {"b": 2}])
    assert str(seen[0].url) == "http://hub.test/api/ingest/ocsf" and seen[0].headers["authorization"] == "Bearer tok"
    assert [json.loads(x) for x in seen[0].content.decode().splitlines()] == [{"a": 1}, {"b": 2}]
    rejecting = HubSink("http://hub.test", "tok", client=httpx.Client(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"rejected": 1}))))
    with pytest.raises(RuntimeError, match="rejected 1"):
        rejecting.send([{}])
    with pytest.raises(ValueError, match="RULES_HUB_URL"):
        HubSink("", "tok")


def test_print_sink():
    out = []
    PrintSink(out.append).send([{"x": 1}])
    assert out == ['{"x":1}']


def test_open_lake_empty_and_parquet(tmp_path):
    con = open_lake(tmp_path / "nolake")
    assert con.execute("SELECT count(*) FROM ocsf_flat").fetchone() == (0,)
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    from detection_rules.lake import flatten
    d = tmp_path / "lake" / "events" / "class_uid=1001" / "dt=2026-10-01" / "hr=09"
    d.mkdir(parents=True)
    row = flatten(shadow_read(NOW, 1))
    row.pop("class_uid")
    row["time"] = pa.scalar(NOW, type=pa.timestamp("ms", tz="UTC"))
    pq.write_table(pa.Table.from_pylist([row]), d / "part-0001.parquet")
    con = open_lake(tmp_path / "lake")
    assert con.execute("SELECT uid, time, class_uid, target_file FROM ocsf_flat").fetchall() == [
        ("ev1", NOW, 1001, "/etc/shadow")]


def test_watch_survives_failures(rules, tmp_path):
    calls = {"n": 0}

    def open_con():
        calls["n"] += 1
        if calls["n"] == 1:
            raise duckdb.IOException("lake moved")
        return memory_lake([shadow_read(NOW - 1000, 1)])

    sink, sleeps = ListSink(), []
    t = iter([NOW / 1000, NOW / 1000 + 60])
    res = watch(shadow_rule(rules), open_con, sink, tmp_path / "state.json", interval_s=30, lookback_s=60,
                overlap_s=10, max_per_rule=10, cycles=2, clock=lambda: next(t), sleep=sleeps.append)
    assert len(res) == 1 and res[0].sent == 1 and sleeps == [30]
    assert State.load(tmp_path / "state.json").watermark == NOW  # the failed cycle never read the clock
