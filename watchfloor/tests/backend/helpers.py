"""Shared builders for Watchfloor tests."""

from __future__ import annotations

from pathlib import Path

from watchfloor import ocsf

ROOT = Path(__file__).resolve().parents[2]  # watchfloor/
SCENARIOS = ROOT / "datasets" / "scenarios"
PORTFOLIO = ROOT.parent


def auth_event(t: int, ok: bool, user: str = "admin", ip: str = "203.0.113.9", host: str = "web01",
               scenario: str | None = None) -> dict:
    e = ocsf.new_event(ocsf.AUTHENTICATION, 1, time=t, product="test",
                       labels=[f"scenario:{scenario}"] if scenario else None)
    e["status_id"] = ocsf.STATUS_SUCCESS if ok else ocsf.STATUS_FAILURE
    e["user"] = {"name": user}
    e["src_endpoint"] = {"ip": ip}
    e["device"] = {"hostname": host}
    return ocsf.validate(e)


def finding(t: int, techniques: list[str], host: str = "web01", title: str = "Rule", pid: int | None = None,
            scenario: str | None = None, product: str = "test") -> dict:
    e = ocsf.new_event(ocsf.DETECTION_FINDING, 1, time=t, product=product, severity_id=ocsf.SEV_HIGH,
                       labels=[f"scenario:{scenario}"] if scenario else None)
    e["finding_info"] = {"uid": e["metadata"]["uid"], "title": title, "attacks": ocsf.attacks(techniques)}
    e["device"] = {"hostname": host}
    if pid is not None:
        e["actor"] = {"process": {"pid": pid}}
    return ocsf.validate(e)


def proc(t: int, pid: int, ppid: int | None, name: str, host: str = "ws01", cmd: str = "") -> dict:
    e = ocsf.new_event(ocsf.PROCESS_ACTIVITY, 1, time=t, product="test")
    e["process"] = {"pid": pid, "name": name, "cmd_line": cmd or name}
    if ppid is not None:
        e["process"]["parent_process"] = {"pid": ppid}
    e["device"] = {"hostname": host}
    return ocsf.validate(e)
