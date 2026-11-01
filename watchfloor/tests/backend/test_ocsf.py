import pytest

from helpers import auth_event, finding
from watchfloor import ocsf


def test_new_event_sets_type_uid_and_metadata():
    e = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 2, time="2026-10-26T09:00:00Z", product="p", uid="u1",
                       correlation_uid="c1", labels=["scenario:x"], message="m")
    assert e["type_uid"] == 100702
    assert e["category_uid"] == 1
    assert e["time"] == 1793005200000
    assert e["metadata"] == {"version": ocsf.OCSF_VERSION, "uid": "u1", "correlation_uid": "c1",
                             "labels": ["scenario:x"], "product": {"name": "p", "vendor_name": "Watchfloor portfolio"}}


def test_unknown_class_rejected():
    with pytest.raises(ocsf.ContractError):
        ocsf.new_event(9999, 1, time=0, product="p")


@pytest.mark.parametrize("value,expected", [
    ("2026-10-26T09:00:00.123456789Z", 1793005200123),
    ("2026-10-26T09:00:00", 1793005200000),
    (1793005200, 1793005200000),
    (1793005200123, 1793005200123),
])
def test_to_epoch_ms(value, expected):
    assert ocsf.to_epoch_ms(value) == expected


def test_to_epoch_ms_datetime_and_now():
    from datetime import datetime

    assert ocsf.to_epoch_ms(datetime(2026, 10, 26, 9)) == 1793005200000
    assert ocsf.to_epoch_ms(None) > 1700000000000
    assert ocsf.iso(1793005200123) == "2026-10-26T09:00:00.123Z"


@pytest.mark.parametrize("score,sev", [(None, 0), (5, 1), (25, 2), (47, 3), (73, 4), (99, 5)])
def test_severity_from_score(score, sev):
    assert ocsf.severity_from_score(score) == sev


def test_severity_from_label():
    assert ocsf.severity_from_label("High") == 4
    assert ocsf.severity_from_label(None) == 0


def test_validate_reports_missing_fields():
    e = ocsf.new_event(ocsf.AUTHENTICATION, 1, time=0, product="p")
    with pytest.raises(ocsf.ContractError, match="user"):
        ocsf.validate(e)


def test_validate_rejects_bad_type_uid_and_class():
    e = auth_event(0, True)
    e["type_uid"] = 1
    with pytest.raises(ocsf.ContractError, match="type_uid"):
        ocsf.validate(e)
    with pytest.raises(ocsf.ContractError, match="unsupported"):
        ocsf.validate({"class_uid": "x"})


def test_validate_rejects_bad_technique_id():
    f = finding(0, ["T1110.001"])
    f["finding_info"]["attacks"][0]["technique"]["uid"] = "not-a-technique"
    with pytest.raises(ocsf.ContractError):
        ocsf.validate(f)


def test_attacks_pairs_names_and_tactics():
    out = ocsf.attacks(["T1110.001", "T1078"], ["Brute", ""], ["TA0006"], ["Credential Access"])
    assert out[0]["technique"] == {"uid": "T1110.001", "name": "Brute"}
    assert out[1]["tactic"] == {"uid": "TA0006", "name": "Credential Access"}
    assert "name" not in out[1]["technique"]


def test_file_obj_windows_path():
    assert ocsf.file_obj("C:\\Users\\x\\a.docx") == {"name": "a.docx", "path": "C:\\Users\\x\\a.docx"}


def test_flatten_finding_and_incident():
    f = finding(1793005200000, ["T1078", "T1110.001", "T1078"], scenario="s1", pid=42)
    row = ocsf.flatten(f)
    assert row["techniques"] == ["T1078", "T1110.001"]
    assert row["scenario"] == "s1"
    assert row["process_pid"] == 42
    inc = ocsf.new_event(ocsf.INCIDENT_FINDING, 1, time=0, product="soar", correlation_uid="INC-1")
    inc["finding_info_list"] = [{"uid": "x", "title": "T"}]
    row = ocsf.flatten(ocsf.validate(inc))
    assert row["finding_uid"] == "INC-1"
    assert row["finding_title"] == "T"
