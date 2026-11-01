"""Tests for the Sigma engine: modifiers, conditions and rule validation."""

import pytest
from conftest import rule_from

from attack_coverage.sigma import ConditionError, SigmaMatcher, SigmaRule, SigmaRuleError, load_rules, parse_condition
from attack_coverage.sigma.condition import And, Not, OfPattern, Or, Ref


def m(detection, event):
    return rule_from(detection).matches(event)


def test_wildcards_case_insensitivity_and_escaping():
    assert m({"s": {"Image": "*\\WHOAMI.exe"}, "condition": "s"}, {"Image": "C:\\Windows\\whoami.EXE"})
    assert m({"s": {"Image": "a?c"}, "condition": "s"}, {"Image": "abc"})
    assert not m({"s": {"Image": "a?c"}, "condition": "s"}, {"Image": "abbc"})
    assert m({"s": {"CommandLine": "100\\*"}, "condition": "s"}, {"CommandLine": "100*"})
    assert not m({"s": {"CommandLine": "100\\*"}, "condition": "s"}, {"CommandLine": "1000"})
    assert not m({"s": {"Image|cased": "Cmd.exe"}, "condition": "s"}, {"Image": "cmd.exe"})


def test_contains_startswith_endswith_and_lists():
    det = {"s": {"CommandLine|contains": ["mimikatz", "sekurlsa"]}, "condition": "s"}
    assert m(det, {"CommandLine": "run SEKURLSA::logonpasswords"})
    assert not m(det, {"CommandLine": "notepad"})
    assert m({"s": {"Image|startswith": "C:\\Users\\"}, "condition": "s"}, {"Image": "c:\\users\\x\\a.exe"})
    assert m({"s": {"Image|endswith": ".ps1"}, "condition": "s"}, {"Image": "x.PS1"})


def test_all_modifier_requires_every_value():
    det = {"s": {"CommandLine|contains|all": ["-nop", "-w hidden"]}, "condition": "s"}
    assert m(det, {"CommandLine": "powershell -nop -w hidden"})
    assert not m(det, {"CommandLine": "powershell -nop"})


def test_windash_expands_dash_variants():
    det = {"s": {"CommandLine|contains|windash": " -enc "}, "condition": "s"}
    for cli in ("p -enc x", "p /enc x", "p \u2013enc x", "p \u2014enc x"):
        assert m(det, {"CommandLine": cli})
    assert not m(det, {"CommandLine": "p enc x"})


def test_regex_cidr_exists_numeric_fieldref_and_null():
    assert m({"s": {"CommandLine|re": r"\bnet\s+user\b"}, "condition": "s"}, {"CommandLine": "net  user bob"})
    assert m(
        {"s": {"DestinationIp|cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "condition": "s"}, {"DestinationIp": "10.2.3.4"}
    )
    assert not m({"s": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "s"}, {"DestinationIp": "not-an-ip"})
    assert m({"s": {"Hashes|exists": True}, "condition": "s"}, {"Hashes": "x"})
    assert m({"s": {"Hashes|exists": False}, "condition": "s"}, {})
    assert m({"s": {"Port|gte": 1024}, "condition": "s"}, {"Port": "8080"})
    assert not m({"s": {"Port|lt": 1024}, "condition": "s"}, {"Port": "x"})
    assert m({"s": {"User|fieldref": "ParentUser"}, "condition": "s"}, {"User": "A\\b", "ParentUser": "a\\B"})
    assert m({"s": {"ParentImage": None}, "condition": "s"}, {"Image": "x"})
    assert not m({"s": {"ParentImage": None}, "condition": "s"}, {"ParentImage": "y"})


def test_list_of_maps_keywords_and_list_valued_fields():
    det = {"s": [{"Image|endswith": "\\a.exe"}, {"Image|endswith": "\\b.exe"}], "condition": "s"}
    assert m(det, {"Image": "C:\\b.exe"})
    assert m({"kw": ["evil-marker"], "condition": "kw"}, {"Message": "has EVIL-MARKER inside"})
    assert m({"s": {"Tags": "x"}, "condition": "s"}, {"Tags": ["y", "x"]})
    assert m({"s": {"Flag": True}, "condition": "s"}, {"Flag": True})


@pytest.mark.parametrize(
    ("cond", "event", "expected"),
    [
        ("sel_a and not sel_b", {"A": "1"}, True),
        ("sel_a and not sel_b", {"A": "1", "B": "1"}, False),
        ("sel_a or sel_b and c", {"A": "1"}, True),  # and binds tighter than or
        ("(sel_a or sel_b) and c", {"A": "1"}, False),
        ("1 of sel_*", {"B": "1"}, True),
        ("all of sel_*", {"A": "1"}, False),
        ("all of sel_*", {"A": "1", "B": "1"}, True),
        ("1 of them", {"C": "1"}, True),
        ("all of them", {"A": "1", "B": "1", "C": "1"}, True),
        ("not not sel_a", {"A": "1"}, True),
    ],
)
def test_conditions(cond, event, expected):
    assert m({"sel_a": {"A": "1"}, "sel_b": {"B": "1"}, "c": {"C": "1"}, "condition": cond}, event) is expected


def test_them_ignores_underscore_helpers():
    assert m({"a": {"A": "1"}, "_helper": {"Z": "1"}, "condition": "all of them"}, {"A": "1"})


def test_condition_ast_and_errors():
    assert parse_condition("a and not (b or c)", "abc") == And((Ref("a"), Not(Or((Ref("b"), Ref("c"))))))
    assert parse_condition("any of x*", ["x1"]) == OfPattern("1", "x*")
    for bad, msg in (
        ("a and", "end"),
        ("a b", "trailing"),
        ("(a", "missing"),
        ("zzz", "unknown"),
        ("1 of q*", "matches no"),
        ("a | count() > 5", "aggregation"),
        ("a = b", "unexpected"),
        ("or a", "unexpected"),
    ):
        with pytest.raises(ConditionError, match=msg):
            parse_condition(bad, ["a", "b", "c"])


def test_multiple_conditions_are_ored():
    assert m({"a": {"A": "1"}, "b": {"B": "1"}, "condition": ["a", "b"]}, {"B": "1"})


@pytest.mark.parametrize(
    ("data", "msg"),
    [
        ({"_drop": "title"}, "missing required field 'title'"),
        (
            {"title": "t", "id": "nope", "logsource": {"product": "w"}, "detection": {"s": {"A": 1}, "condition": "s"}},
            "UUID",
        ),
        ({"status": "bogus"}, "status"),
        ({"level": "urgent"}, "level"),
        ({"date": "26/10/2026"}, "date"),
        ({"logsource": {"foo": "bar"}}, "logsource"),
        ({"tags": ["Attack.T1059"]}, "invalid tags"),
        ({"detection": {"s": {"A": 1}}}, "condition is required"),
        ({"detection": {"condition": "s"}}, "no selections"),
        ({"detection": {"s": {"A|base64offset|contains": "x"}, "condition": "s"}}, "not supported"),
        ({"detection": {"s": {"A|frobnicate": "x"}, "condition": "s"}}, "not supported"),
        ({"detection": {"s": {}, "condition": "s"}}, "empty"),
        ({"detection": {"s": "just a string", "condition": "s"}}, "must be a map"),
        ({"detection": {"s": {"A|re": "("}, "condition": "s"}}, "missing"),
        ({"detection": {"s": {"A": 1}, "condition": "t"}}, "unknown identifier"),
        ({"correlation": {}}, "correlation"),
    ],
)
def test_rule_validation(data, msg):
    base = {
        "title": "t",
        "id": "00000000-0000-4000-8000-000000000001",
        "logsource": {"product": "windows"},
        "detection": {"s": {"A": 1}, "condition": "s"},
    }
    merged = {**base, **data}
    merged.pop(merged.pop("_drop", None), None)
    with pytest.raises(SigmaRuleError, match=msg):
        SigmaRule.from_dict(merged)


def test_logsource_scoping_and_matcher(rules):
    matcher = SigmaMatcher(rules)
    linux_whoami = {"Image": "/usr/bin/whoami", "_logsource": {"category": "process_creation", "product": "linux"}}
    hits = matcher.match([linux_whoami])
    assert [h.rule_title for h in hits] == ["Linux Current User Discovery"]
    assert matcher.match([linux_whoami], rule_ids=["ce753259-9469-4fd9-9727-fd242d084d4f"]) == []


def test_bundled_rules_load_with_attack_tags(rules):
    assert len(rules) == 11
    assert all(r.techniques for r in rules)
    assert {"T1059.001", "T1082"} <= {t for r in rules for t in r.techniques}


def test_duplicate_ids_and_multi_document_files(tmp_path):
    doc = (
        "title: a\nid: 00000000-0000-4000-8000-000000000009\nlogsource: {product: linux}\n"
        "detection: {s: {A: 1}, condition: s}\n"
    )
    (tmp_path / "one.yml").write_text(doc + "---\n" + doc.replace("title: a", "title: b"))
    with pytest.raises(SigmaRuleError, match="duplicate rule id"):
        load_rules([tmp_path])
    (tmp_path / "one.yml").write_text(doc + "---\n")
    assert len(load_rules([tmp_path / "one.yml"])) == 1
