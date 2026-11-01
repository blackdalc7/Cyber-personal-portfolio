import json

import pytest

from helpers import PORTFOLIO
from watchfloor import ocsf
from watchfloor.mappers import map_record

ECS_AUTH = {"@timestamp": "2026-10-26T11:00:00.000Z", "message": "Failed password",
            "event": {"id": "e1", "kind": "event", "category": ["authentication"], "action": "ssh_login",
                      "outcome": "failure"},
            "host": {"hostname": "web01"}, "process": {"name": "sshd", "pid": 7},
            "source": {"ip": "203.0.113.9", "port": 4242}, "user": {"name": "admin"}}


def test_ecs_authentication():
    out = map_record("siem", ECS_AUTH, scenario="s")
    assert out["class_uid"] == ocsf.AUTHENTICATION
    assert out["status_id"] == ocsf.STATUS_FAILURE
    assert out["src_endpoint"] == {"ip": "203.0.113.9", "port": 4242}
    assert out["device"]["hostname"] == "web01"
    assert out["auth_protocol"] == "sshd"
    assert out["metadata"]["labels"] == ["scenario:s"]


def test_ecs_iam_and_process():
    iam = {**ECS_AUTH, "event": {"id": "e2", "kind": "event", "category": ["iam"], "action": "user_created",
                                 "outcome": "success"}, "user": {"name": "svc", "target": {"name": "svc-backup"}}}
    out = map_record("siem", iam)
    assert out["class_uid"] == ocsf.ACCOUNT_CHANGE and out["user"]["name"] == "svc-backup"
    proc = {**ECS_AUTH, "event": {"id": "e3", "kind": "event", "category": ["process"], "action": "sudo"},
            "process": {"name": "C:\\Windows\\cmd.exe", "pid": 9, "command_line": "cmd /c x",
                        "parent": {"name": "winword.exe", "pid": 3}}}
    out = map_record("siem", proc)
    assert out["class_uid"] == ocsf.PROCESS_ACTIVITY
    assert out["process"]["name"] == "cmd.exe"
    assert out["process"]["file"]["path"] == "C:\\Windows\\cmd.exe"
    assert out["process"]["parent_process"] == {"pid": 3, "name": "winword.exe"}
    assert out["process"]["user"] == {"name": "admin"}


def test_ecs_event_without_class_is_skipped():
    other = {**ECS_AUTH, "event": {"id": "e4", "kind": "event", "category": ["network"]}}
    assert map_record("siem", other) is None


def test_ecs_alert_and_chain():
    alert = {"@timestamp": "2026-10-26T11:01:03.000Z", "message": "[HIGH] brute",
             "event": {"id": "a1", "kind": "alert", "severity": 73, "reason": "10 failures"},
             "rule": {"id": "SIEM-AUTH-001", "name": "Brute force", "description": "d"},
             "threat": {"technique": {"id": ["T1110.001"], "name": ["Password Guessing"]},
                        "tactic": {"id": ["TA0006"], "name": ["Credential Access"]}},
             "source": {"ip": "203.0.113.9"}, "related": {"hosts": ["web01"]}, "user": {"name": "admin"},
             "siem": {"alert": {"trigger_event_ids": ["x", "y"]}}, "file": {"path": "/etc/shadow"}}
    out = map_record("siem", alert)
    info = out["finding_info"]
    assert out["class_uid"] == ocsf.DETECTION_FINDING
    assert out["severity_id"] == ocsf.SEV_HIGH and out["risk_score"] == 73
    assert info["analytic"]["uid"] == "SIEM-AUTH-001"
    assert info["attacks"][0]["tactic"]["name"] == "Credential Access"
    assert info["related_events"] == [{"uid": "x"}, {"uid": "y"}]
    assert info["desc"] == "10 failures"
    assert out["device"] == {"hostname": "web01"}
    assert out["actor"]["user"]["name"] == "admin"
    assert out["unmapped"]["file.path"] == "/etc/shadow"
    chain = {**alert, "siem": {"chain": {"id": "c1", "alert_ids": ["a1"], "verdict": "True Positive",
                                         "attack_stage": "initial_access"}}}
    out = map_record("siem", chain)
    assert out["metadata"]["correlation_uid"] == "c1"
    assert out["finding_info"]["types"] == ["chain"]
    assert out["unmapped"]["chain"]["verdict"] == "True Positive"


def test_edr_raw_records():
    start = {"Type": "ProcessStart", "TimeStamp": "2026-10-26T09:00:12Z", "ProcessId": 3150, "ParentProcessId": 3100,
             "ImageName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c x"}
    out = map_record("edr-raw", start, host="ws01")
    assert out["process"]["parent_process"] == {"pid": 3100}
    stop = {"Type": "ProcessStop", "TimeStamp": "2026-10-26T09:00:14Z", "ProcessId": 3100, "ImageName": "WINWORD.EXE"}
    assert map_record("edr-raw", stop)["activity_id"] == 2
    write = {"Type": "DiskWrite", "TimeStamp": "2026-10-26T09:00:26Z", "ProcessId": 4100, "FilePath": "\\a\\b.docx",
             "Size": 4096}
    out = map_record("edr-raw", write)
    assert out["class_uid"] == ocsf.FILE_ACTIVITY and out["activity_id"] == 3 and out["file"]["size"] == 4096
    assert map_record("edr-raw", {"Type": "Bogus", "TimeStamp": "x", "ProcessId": 1}) is None
    assert map_record("edr-raw", {"Type": "ProcessStart"}) is None


def test_meta_alerts_from_06_example():
    q = json.loads((PORTFOLIO / "06-alert-clustering-fp-reducer/examples/output/queue.json").read_text())
    docs = [map_record("triage", i, run_time="2026-10-26T15:00:00Z") for i in q["queue"] + q["suppressed"]]
    assert len(docs) == len(q["queue"]) + len(q["suppressed"])
    suppressed = [d for d in docs if "suppress" in d["finding_info"]["types"]]
    assert suppressed and all(d["severity_id"] == ocsf.SEV_INFO for d in suppressed)
    assert docs[0]["unmapped"]["disposition"] == q["queue"][0]["disposition"]


def _incident(status, **kw):
    base = {"id": "INC-1", "title": "Brute force", "severity": "critical", "status": status, "host": "web01",
            "indicator_ip": "203.0.113.9", "external_id": "c1", "detected_at": 100.0, "created_at": 101.0,
            "approval_requested_at": 102.0, "risk_score": 80, "source": "ecs", "description": "d"}
    return {**base, **kw}


@pytest.mark.parametrize("status,activity,status_id", [
    ("new", 1, ocsf.INC_NEW), ("awaiting_approval", 2, ocsf.INC_ON_HOLD), ("remediated", 3, ocsf.INC_RESOLVED),
    ("rejected", 3, ocsf.INC_CLOSED), ("weird", 2, 99)])
def test_incident_states(status, activity, status_id):
    out = map_record("soar", _incident(status, decided_by="dana", decided_at=150.0))
    assert out["activity_id"] == activity and out["status_id"] == status_id
    assert out["metadata"]["correlation_uid"] == "INC-1"
    assert out["time"] == 150_000
    assert out["assignee"] == {"name": "dana"}
    assert out["unmapped"]["timing"]["decided_at"] == 150.0


TG_EXEC = {"process_exec": {"process": {"exec_id": "abc", "pid": 51, "uid": 0, "binary": "/usr/bin/cat",
                                        "arguments": "/etc/shadow",
                                        "pod": {"namespace": "atomic", "name": "runner",
                                                "container": {"name": "c", "image": {"name": "img:1"}}}},
                            "parent": {"pid": 50, "binary": "/bin/bash"}},
           "node_name": "lab-k8s", "time": "2026-10-26T12:00:00.123456789Z"}


def test_tetragon_exec_exit_and_kprobes():
    out = map_record("tetragon", TG_EXEC)
    assert out["process"]["cmd_line"] == "/usr/bin/cat /etc/shadow"
    assert out["process"]["user"] == {"uid": "0", "name": "root"}
    assert out["process"]["parent_process"]["name"] == "bash"
    assert out["unmapped"]["k8s"]["namespace"] == "atomic"
    assert out["device"]["hostname"] == "lab-k8s"
    exit_ = {"process_exit": TG_EXEC["process_exec"], "node_name": "n", "time": "2026-10-26T12:00:01Z"}
    assert map_record("tetragon", exit_)["activity_id"] == 2
    file_kp = {"process_kprobe": {"process": {"pid": 51, "binary": "/usr/bin/cat"}, "function_name":
                                  "security_file_permission", "args": [{"file_arg": {"path": "/etc/shadow"}},
                                                                       {"int_arg": 4}], "policy_name": "sensitive"},
               "node_name": "n", "time": "2026-10-26T12:00:02Z"}
    out = map_record("tetragon", file_kp)
    assert out["class_uid"] == ocsf.FILE_ACTIVITY and out["activity_id"] == 2
    assert out["unmapped"]["kprobe"]["policy"] == "sensitive"
    net_kp = {"process_kprobe": {"process": {"pid": 52, "binary": "/usr/bin/curl"}, "function_name": "tcp_connect",
                                 "args": [{"sock_arg": {"saddr": "10.1.0.5", "sport": 40000, "daddr": "1.2.3.4",
                                                        "dport": 443, "protocol": "TCP"}}]},
              "node_name": "n", "time": "2026-10-26T12:00:03Z"}
    out = map_record("tetragon", net_kp)
    assert out["class_uid"] == ocsf.NETWORK_ACTIVITY and out["dst_endpoint"]["port"] == 443
    other = {"process_kprobe": {"process": {"pid": 53, "binary": "/bin/x"}, "function_name": "sys_setuid",
                                "args": [{"int_arg": 0}]}, "node_name": "n", "time": "2026-10-26T12:00:04Z"}
    assert map_record("tetragon", other)["activity_id"] == 99
    assert map_record("tetragon", {"process_unknown": {}}) is None


SYSMON_1 = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Computer": "ws01",
            "TimeCreated": "2026-10-26 09:00:12.000", "EventRecordID": 10,
            "Message": "Process Create:\nImage: C:\\Windows\\System32\\cmd.exe\nCommandLine: cmd.exe /c whoami\n"
                       "ProcessId: 3150\nUser: LAB\\dana\nParentProcessId: 3100\n"
                       "ParentImage: C:\\Program Files\\Office\\WINWORD.EXE\nParentCommandLine: WINWORD.EXE x.docm"}


def test_winlog_sysmon_and_security():
    out = map_record("winlog", SYSMON_1)
    assert out["process"]["pid"] == 3150
    assert out["process"]["parent_process"]["name"] == "WINWORD.EXE"
    assert out["metadata"]["uid"] == "ws01-sysmon-10"
    file_ = {**SYSMON_1, "EventID": 11, "Message": "File created:\nImage: C:\\x\\a.exe\nProcessId: 7\n"
             "TargetFilename: C:\\Users\\Public\\x.dll"}
    assert map_record("winlog", file_)["file"]["name"] == "x.dll"
    net = {**SYSMON_1, "EventID": 3, "Message": "Network:\nSourceIp: 10.0.0.2\nSourcePort: 5000\n"
           "DestinationIp: 1.2.3.4\nDestinationPort: 443\nProtocol: tcp"}
    assert map_record("winlog", net)["dst_endpoint"] == {"ip": "1.2.3.4", "port": 443}
    assert map_record("winlog", {**SYSMON_1, "EventID": 5}) is None
    inserts = [""] * 20
    inserts[5] = "dana"
    inserts[19] = "10.0.0.9"
    sec = {"Channel": "Security", "EventID": 4625, "Computer": "ws01", "TimeCreated": "2026-10-26T09:00:00Z",
           "StringInserts": inserts, "EventRecordID": 3}
    out = map_record("winlog", sec)
    assert out["status_id"] == ocsf.STATUS_FAILURE and out["src_endpoint"] == {"ip": "10.0.0.9"}
    assert map_record("winlog", {"Channel": "System", "EventID": 1}) is None


def test_ocsf_passthrough_and_unknown_source():
    doc = map_record("siem", ECS_AUTH)
    assert map_record("ocsf", doc) is doc
    with pytest.raises(ValueError):
        map_record("nope", {})
