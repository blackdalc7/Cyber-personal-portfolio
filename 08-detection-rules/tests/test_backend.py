from __future__ import annotations

import pytest
from conftest import rule_yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from detection_rules.backend import DuckDBBackend
from detection_rules.lake import memory_lake
from detection_rules.testing import envelope


def sql(detection: str, category: str = "process_creation") -> str:
    return DuckDBBackend().convert(SigmaCollection.from_yaml(rule_yaml(detection, category)))[0]


def proc(path: str, cmd: str = "", parent: str | None = None, user: str | None = None, i: int = 0) -> dict:
    p = {"name": path.replace("\\", "/").rsplit("/", 1)[-1], "file": {"path": path}, "cmd_line": cmd}
    if parent:
        p["parent_process"] = {"file": {"path": parent}, "cmd_line": f"{parent} -x"}
    if user:
        p["user"] = {"name": user}
    return envelope({"class_uid": 1007, "activity_id": 1, "process": p}, uid=f"e{i}-{path}")


def hits(query: str, docs: list[dict]) -> list[str]:
    con = memory_lake(docs)
    return sorted(r[0] for r in con.execute(query, [0, 2**62]).fetchall())


def test_injection_is_inert():
    q = sql("  sel:\n    CommandLine|contains: \"x' OR 1=1 --\"\n  condition: sel")
    assert "'%x'' OR 1=1 --%'" in q
    assert hits(q, [proc("C:\\a.exe", "harmless"), proc("C:\\b.exe", "x' OR 1=1 --", i=1)]) == ["e1-C:\\b.exe"]


def test_like_metacharacters_are_literal():
    q = sql("  sel:\n    CommandLine|contains: '100%_done'\n  condition: sel")
    assert hits(q, [proc("C:\\a.exe", "100%_done"), proc("C:\\b.exe", "100xxdone", i=1)]) == ["e0-C:\\a.exe"]


def test_backslashes_and_sigma_wildcards():
    q = sql("  sel:\n    Image: 'C:\\Tools\\\\*\\run?.exe'\n  condition: sel")
    docs = [proc("C:\\Tools\\x\\run1.exe"), proc("C:\\Tools\\x\\run12.exe", i=1), proc("C:/Tools/x/run1.exe", i=2)]
    assert hits(q, docs) == ["e0-C:\\Tools\\x\\run1.exe"]


def test_case_insensitive_by_default_cased_when_asked():
    docs = [proc("C:\\A.EXE", "WHOAMI"), proc("C:\\b.exe", "whoami", i=1)]
    assert len(hits(sql("  sel:\n    CommandLine: whoami\n  condition: sel"), docs)) == 2
    assert hits(sql("  sel:\n    CommandLine|cased: whoami\n  condition: sel"), docs) == ["e1-C:\\b.exe"]


def test_not_filter_keeps_events_without_the_field():
    q = sql("  sel:\n    Image|endswith: '\\cmd.exe'\n  filt:\n    ParentImage|startswith: 'C:\\Windows\\'\n"
            "  condition: sel and not filt")
    docs = [proc("C:\\Windows\\System32\\cmd.exe"),  # no parent at all: must still match
            proc("C:\\Windows\\System32\\cmd.exe", parent="C:\\Windows\\explorer.exe", i=1),
            proc("C:\\Windows\\System32\\cmd.exe", parent="C:\\Users\\x\\evil.exe", i=2)]
    assert hits(q, docs) == ["e0-C:\\Windows\\System32\\cmd.exe", "e2-C:\\Windows\\System32\\cmd.exe"]


def test_regex_numbers_null_and_exists():
    q = sql("  sel:\n    CommandLine|re: '^net\\s+(user|group)'\n  condition: sel")
    assert hits(q, [proc("C:\\net.exe", "net user"), proc("C:\\net.exe", "net view", i=1)]) == ["e0-C:\\net.exe"]
    assert "'it''s'" in sql("  sel:\n    CommandLine|re: \"it's\"\n  condition: sel")
    q = sql("  sel:\n    User: null\n  condition: sel")
    assert hits(q, [proc("C:\\a.exe"), proc("C:\\b.exe", user="bob", i=1)]) == ["e0-C:\\a.exe"]
    q = sql("  sel:\n    User|exists: true\n  condition: sel")
    assert hits(q, [proc("C:\\a.exe"), proc("C:\\b.exe", user="bob", i=1)]) == ["e1-C:\\b.exe"]
    assert "ParentProcessId" not in sql("  sel:\n    ParentProcessId: 4\n  condition: sel")


def net(port: int, i: int) -> dict:
    return envelope({"class_uid": 4001, "activity_id": 1, "dst_endpoint": {"ip": "10.0.0.1", "port": port},
                     "src_endpoint": {"ip": "10.0.0.2", "port": 50000}}, uid=f"n{i}")


def test_network_numbers_and_comparisons():
    q = sql("  sel:\n    DestinationPort: 445\n  condition: sel", "network_connection")
    assert "class_uid = 4001" in q
    assert hits(q, [net(445, 0), net(80, 1)]) == ["n0"]
    q = sql("  sel:\n    DestinationPort|gte: 1024\n    DestinationIp: 10.0.0.1\n  condition: sel",
            "network_connection")
    assert hits(q, [net(445, 0), net(8080, 1)]) == ["n1"]
    for op, expect in (("lt", ["n0"]), ("lte", ["n0"]), ("gt", ["n1"])):
        q = sql(f"  sel:\n    DestinationPort|{op}: 445\n  condition: sel", "network_connection")
        assert hits(q, [net(80, 0), net(8080, 1)]) == expect


def test_categories_select_the_right_class():
    for cat, frag in (("file_access", "activity_id = 2"), ("file_event", "activity_id IN (1, 3)"),
                      ("file_delete", "activity_id = 4")):
        assert frag in sql("  sel:\n    TargetFilename|endswith: '.dmp'\n  condition: sel", cat)


def test_unsupported_things_fail_loudly():
    with pytest.raises(SigmaError, match="no OCSF class mapping"):
        sql("  sel:\n    Image: x\n  condition: sel", "registry_set")
    with pytest.raises(SigmaError, match="no OCSF mapping"):
        sql("  sel:\n    TargetObject: x\n  condition: sel")
