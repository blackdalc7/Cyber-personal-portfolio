from __future__ import annotations

import json

import anyio
import pytest
from conftest import MALDOC, SCANNER, SSH
from mcp.server.mcpserver.exceptions import ToolError

from ai_analyst.tools import MAX_TEXT, clip

T0 = 1_793_005_200_000  # 2026-10-26T09:00:00Z


def call(server, name: str, **args):
    res = anyio.run(server.call_tool, name, args)
    return json.loads(res.content[0].text)


def test_every_tool_is_read_only(server) -> None:
    tools = anyio.run(server.list_tools)
    assert {t.name for t in tools} == {"list_incidents", "get_incident", "search_events", "get_findings",
                                       "process_ancestry", "auth_summary", "lookup_asset", "check_ip"}
    for t in tools:
        assert t.annotations.read_only_hint is True and t.annotations.destructive_hint is False
        assert t.description and t.input_schema["type"] == "object"


def test_list_and_get_incident(server) -> None:
    listed = call(server, "list_incidents")
    ids = {i["id"] for i in listed["incidents"]}
    assert {MALDOC, SSH, SCANNER} <= ids
    assert {i["status"] for i in call(server, "list_incidents", status="remediated")["incidents"]} == {"remediated"}
    inc = call(server, "get_incident", incident_id=MALDOC)
    assert inc["incident"]["host"] == "ws01" and inc["incident"]["status"] == "remediated"
    assert [h["status"] for h in inc["history"]][-1] == "remediated"
    titles = {f["finding_title"] for f in inc["related_findings"]["rows"]}
    assert "Office application spawned a shell or script host" in titles


def test_unknown_incident_and_bad_ids(server) -> None:
    with pytest.raises(ToolError, match="no incident"):
        call(server, "get_incident", incident_id="INC-NOPE")
    with pytest.raises(ToolError, match="pattern"):
        call(server, "get_incident", incident_id="INC-1' OR 1=1 --")


def test_search_events(server) -> None:
    res = call(server, "search_events", since_ms=T0, until_ms=T0 + 3600_000, hostname="ws01", class_uid=1007,
               text="-enc", limit=5)
    assert res["rows"] and all("-enc" in r["cmd_line"].lower() for r in res["rows"])
    assert all(r["time_utc"].startswith("2026-10-26T09") for r in res["rows"])


def test_injection_shaped_text_is_only_a_literal(server) -> None:
    res = call(server, "search_events", since_ms=T0, until_ms=T0 + 3600_000, text="') OR 1=1 --")
    assert res == {"rows": [], "returned": 0, "truncated": False}


def test_limits_and_windows(server, box) -> None:
    res = call(server, "search_events", since_ms=T0, until_ms=T0 + 3600_000, hostname="ws01", limit=3)
    assert res["returned"] == 3 and res["truncated"] is True
    with pytest.raises(ToolError, match="7 days"):
        call(server, "search_events", since_ms=0, until_ms=T0)
    with pytest.raises(ToolError, match="before"):
        call(server, "auth_summary", since_ms=T0, until_ms=T0 - 1)
    with pytest.raises(ToolError, match="less than or equal"):
        call(server, "search_events", since_ms=T0, until_ms=T0 + 1, limit=1000)
    box.max_rows = 2
    assert call(server, "get_findings", hostname="ws01", limit=50)["returned"] == 2


def test_findings_by_technique_parent(server) -> None:
    rows = call(server, "get_findings", technique="T1059")["rows"]
    assert rows and all(any(t.startswith("T1059") for t in r["techniques"]) for r in rows)
    with pytest.raises(ToolError):
        call(server, "get_findings", technique="T1059; DROP")


def test_process_ancestry(server) -> None:
    res = call(server, "process_ancestry", hostname="ws01", pid=3150, at_ms=T0 + 3600_000)
    names = [p["process_name"] for p in res["ancestry"]]
    assert names[:2] == ["cmd.exe", "WINWORD.EXE"]
    assert call(server, "process_ancestry", hostname="ws01", pid=999999)["found"] is False


def test_auth_summary(server) -> None:
    rows = call(server, "auth_summary", since_ms=1_793_000_000_000, until_ms=1_793_020_000_000,
                src_ip="203.0.113.66")["rows"]
    by = {(r["user_name"], r["outcome"]): r["attempts"] for r in rows}
    assert by[("admin", "failure")] > 10 and by[("admin", "success")] == 1
    with pytest.raises(ToolError, match="not an IP"):
        call(server, "auth_summary", since_ms=T0, until_ms=T0 + 1, src_ip="x' or 1=1")


def test_lookup_asset_and_maintenance(server) -> None:
    res = call(server, "lookup_asset", hostname="fs01", at_ms=1_793_140_870_000)  # 2026-10-27T22:41:10Z
    assert res["asset"]["role"] == "file server"
    assert res["maintenance_at_time"]["reason"].startswith("CHG-20517")
    assert call(server, "lookup_asset", ip="10.20.4.41", at_ms=T0)["maintenance_at_time"] is None
    assert call(server, "lookup_asset", hostname="ghost")["found"] is False
    with pytest.raises(ToolError, match="hostname or ip"):
        call(server, "lookup_asset")


def test_check_ip(server) -> None:
    scanner = call(server, "check_ip", ip="10.0.5.3")
    assert scanner["scope"] == "private" and scanner["authorized_scanner"]["owner"] == "secops-vuln-mgmt"
    assert scanner["seen_in_lake"]["hosts"] == ["db01"]
    ext = call(server, "check_ip", ip="203.0.113.66")
    assert ext["scope"] == "documentation" and ext["asset"] is None and ext["seen_in_lake"]["events"] > 40
    assert call(server, "check_ip", ip="8.8.8.8")["scope"] == "public"
    assert call(server, "check_ip", ip="127.0.0.1")["scope"] == "loopback"
    assert call(server, "check_ip", ip="10.30.10.31")["asset"] == {"hostname": "ws01", "role": "finance workstation"}


def test_clip() -> None:
    long = "A" * (MAX_TEXT + 50)
    out = clip({"a": [long, 1], "b": {"c": long}})
    assert out["a"][0].endswith("…[clipped]") and len(out["a"][0]) == MAX_TEXT + len("…[clipped]")
    assert out["a"][1] == 1 and out["b"]["c"] == out["a"][0]
