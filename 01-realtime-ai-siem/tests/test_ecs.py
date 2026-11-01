"""Tests for mapping syslog messages to ECS 8.11 events."""

import copy

import pytest
from helpers import make_event

from realtime_siem.ecs import ECSValidationError, flatten, validate


def test_failed_login_mapping():
    ev = make_event("Failed password for invalid user oracle from 198.51.100.23 port 51234 ssh2")
    assert ev["event"]["kind"] == "event"
    assert ev["event"]["category"] == ["authentication"]
    assert ev["event"]["type"] == ["start"]
    assert ev["event"]["outcome"] == "failure"
    assert ev["event"]["action"] == "ssh_login"
    assert ev["source"] == {"ip": "198.51.100.23", "port": 51234}
    assert ev["user"]["name"] == "oracle"
    assert "invalid_user" in ev["tags"]
    assert ev["related"]["ip"] == ["198.51.100.23"]
    assert ev["ecs"]["version"] == "8.11.0"
    assert ev["log"]["syslog"]["facility"]["name"] == "authpriv"
    assert ev["process"] == {"name": "sshd", "pid": 100}


def test_sudo_mapping():
    ev = make_event("   admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
                    app="sudo")
    assert ev["event"]["action"] == "sudo"
    assert ev["event"]["category"] == ["process"]
    assert ev["user"]["name"] == "admin"
    assert ev["user"]["effective"]["name"] == "root"
    assert ev["process"]["command_line"] == "/usr/bin/cat /etc/shadow"
    assert ev["process"]["working_directory"] == "/home/admin"
    assert ev["related"]["user"] == ["admin", "root"]


def test_sudo_failure_mapping():
    ev = make_event("alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
                    app="sudo")
    assert ev["event"]["category"] == ["authentication"] and ev["event"]["outcome"] == "failure"


def test_useradd_and_group_mapping():
    ev = make_event("new user: name=svc-backup, UID=1005, GID=1005", app="useradd")
    assert ev["event"]["category"] == ["iam"] and ev["event"]["type"] == ["user", "creation"]
    assert ev["user"]["target"]["name"] == "svc-backup"
    ev = make_event("add 'svc-backup' to group 'sudo'", app="usermod")
    assert ev["event"]["action"] == "user_added_to_group" and ev["group"]["name"] == "sudo"


def test_ipv6_source():
    ev = make_event("Failed password for root from 2001:db8::1 port 22 ssh2")
    assert ev["source"]["ip"] == "2001:db8::1"


def test_windows_json_over_syslog():
    ev = make_event('{"EventID": 4625, "Hostname": "DC01", "TargetUserName": "jsmith", '
                    '"TargetDomainName": "CORP", "IpAddress": "10.1.1.50"}', app="MSWinEventLog")
    assert ev["event"]["code"] == "4625"
    assert ev["event"]["outcome"] == "failure"
    assert ev["host"]["hostname"] == "DC01"
    assert ev["user"] == {"name": "jsmith", "domain": "CORP"}
    assert ev["source"]["ip"] == "10.1.1.50"


def test_unclassified_message_still_valid():
    ev = make_event("CRON[123]: (root) CMD (run-parts /etc/cron.hourly)", app="CRON")
    assert ev["event"]["category"] == ["host"] and ev["event"]["outcome"] == "unknown"


def test_validator_rejects_unknown_field():
    ev = make_event("hello")
    ev["src_ip"] = "1.2.3.4"
    with pytest.raises(ECSValidationError, match="src_ip"):
        validate(ev)


@pytest.mark.parametrize("path,value", [
    (("source", "ip"), "not-an-ip"),
    (("event", "category"), ["made_up"]),
    (("event", "outcome"), "maybe"),
    (("process", "pid"), "123"),
    (("@timestamp",), "yesterday"),
])
def test_validator_rejects_bad_values(path, value):
    ev = copy.deepcopy(make_event("Failed password for root from 1.2.3.4 port 22 ssh2"))
    node = ev
    for p in path[:-1]:
        node = node.setdefault(p, {})
    node[path[-1]] = value
    with pytest.raises(ECSValidationError):
        validate(ev)


def test_validator_requires_core_fields():
    with pytest.raises(ECSValidationError, match="missing"):
        validate({"message": "x"})


def test_validator_rejects_bad_label_keys():
    ev = make_event("hello")
    ev["labels"] = {"Bad-Key": "x"}
    with pytest.raises(ECSValidationError):
        validate(ev)


def test_attacker_controlled_username_cannot_inject_fields():
    ev = make_event('Failed password for {"x":1} from 1.2.3.4 port 22 ssh2')
    assert ev["user"]["name"] == '{"x":1}'
    validate(ev)
    assert all(isinstance(k, str) for k in flatten(ev))
