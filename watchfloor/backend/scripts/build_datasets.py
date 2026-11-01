"""Rebuild the recorded scenario datasets from the portfolio projects' own code and fixtures.

    python scripts/build_datasets.py            # from watchfloor/, with 01 and 02 dependencies installed

Scenario ``ssh-bruteforce-to-persistence``
    01's fixture ``tests/fixtures/auth.log`` is pushed through 01's real ``Pipeline``
    (offline summariser). The final chain is sent to 02's real ``SoarService`` state
    machine, and an analyst approval is simulated four minutes later; remediation runs
    02's ``mock_isolate.py`` in dry-run mode.

Scenario ``maldoc-to-ransomware``
    03's fixture ``maldoc_ransomware_chain.ndjson`` supplies the process and file
    telemetry. 03 is PowerShell, so its five alerts are transcribed from the documented
    output of ``Invoke-SafeSimulation.ps1`` (the same counts its Pester tests assert),
    using 03's own alert shape. The 02 incident is produced as above.

Everything that is simulated rather than recorded is listed under ``simulated_parts``
in each ``scenario.yml`` and shown in the UI.
"""

from __future__ import annotations

import json
import sys
import tempfile
import uuid
from concurrent.futures import Executor, Future
from pathlib import Path

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent
WF = BACKEND.parent
ROOT = WF.parent
sys.path[:0] = [str(BACKEND / "src"), str(ROOT / "01-realtime-ai-siem" / "src"), str(ROOT / "02-hitl-soar-bot" / "src")]

from watchfloor import ocsf  # noqa: E402
from watchfloor.mappers import map_record  # noqa: E402

OUT = WF / "datasets" / "scenarios"
APPROVER = "U0WATCHFLOOR"


class _Sync(Executor):
    def submit(self, fn, /, *args, **kwargs):
        fut: Future = Future()
        fut.set_result(fn(*args, **kwargs))
        return fut


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def run_soar(alert: dict, detected_s: float, decide_after_s: float, scenario: str) -> list[dict]:
    """Drive 02's real state machine for one alert; return an Incident Finding per state."""
    from soar_bot.chat.outbox import OutboxChat
    from soar_bot.db import Database
    from soar_bot.enrichment import Enricher
    from soar_bot.ingest import normalise
    from soar_bot.remediation import Remediator
    from soar_bot.service import SoarService

    tmp = Path(tempfile.mkdtemp())
    clock = _Clock(detected_s + 2)
    db = Database(tmp / "soar.db", clock=clock)
    svc = SoarService(db=db, chat=OutboxChat(tmp / "outbox"), enricher=Enricher(""),
                      remediator=Remediator(ROOT / "02-hitl-soar-bot" / "scripts" / "mock_isolate.py",
                                            tmp / "iso.json", 30, dry_run=True),
                      approvers=frozenset({APPROVER}), approval_ttl_s=3600, executor=_Sync(), clock=clock)
    snapshots = []
    incident, _ = svc.handle_alert(normalise(alert, received_at=clock()))
    snapshots.append(incident.to_dict())
    clock.t = detected_s + decide_after_s
    nonce = db.get(incident.id).approval_nonce
    outcome = svc.decide(incident.id, nonce, "approve", APPROVER, "analyst.dana", "slack")
    assert outcome.accepted, outcome.message
    snapshots.append(db.get(incident.id).to_dict())
    return [map_record("soar", s, scenario=scenario) for s in snapshots]


def write(scenario_dir: Path, events: list[dict]) -> None:
    scenario_dir.mkdir(parents=True, exist_ok=True)
    events.sort(key=lambda e: e["time"])
    with (scenario_dir / "events.ndjson").open("w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(json.dumps(ocsf.validate(e), separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n")
    print(f"{scenario_dir.name}: {len(events)} events")


def build_ssh() -> None:
    from realtime_siem.config import Settings
    from realtime_siem.llm import build_summarizer
    from realtime_siem.pipeline import Pipeline
    from realtime_siem.replay import iter_datagrams

    sid = "ssh-bruteforce-to-persistence"
    tmp = Path(tempfile.mkdtemp())
    settings = Settings(output_dir=tmp)
    pipe = Pipeline(settings, build_summarizer(settings))
    for dgram in iter_datagrams(ROOT / "01-realtime-ai-siem" / "tests" / "fixtures" / "auth.log", "5424", 2026):
        for chain in pipe.ingest(dgram, ("10.0.0.5", 514)):
            pipe.summarize_snapshot(pipe.snapshot(chain))
    pipe.flush()
    pipe.close()

    docs = {name: [json.loads(line) for line in (tmp / f"{name}.ndjson").read_text().splitlines() if line]
            for name in ("events", "alerts", "chains")}
    chain_of = {}
    for ch in docs["chains"]:
        for aid in ch["siem"]["chain"]["alert_ids"]:
            chain_of.setdefault(aid, ch["siem"]["chain"]["id"])
    events = []
    for d in docs["events"] + docs["chains"]:
        mapped = map_record("siem", d, scenario=sid)
        if mapped:
            events.append(mapped)
    for d in docs["alerts"]:
        mapped = map_record("siem", d, scenario=sid)
        if d["event"]["id"] in chain_of:
            mapped["metadata"]["correlation_uid"] = chain_of[d["event"]["id"]]
        events.append(ocsf.validate(mapped))
    full_chain = max(docs["chains"], key=lambda c: (c["siem"]["chain"]["alert_count"], c["@timestamp"]))
    detected = ocsf.to_epoch_ms(full_chain["@timestamp"]) / 1000
    events += run_soar(full_chain, detected, 4 * 60 + 10, sid)
    write(OUT / sid, events)


def _edr_alert(rule_id, name, severity, mitre, ts, pid, image, message, *, cmd=None, parent=None, file=None,
               ancestry=None, distinct=None):
    score = {"high": 73, "critical": 99}[severity]
    doc = {"@timestamp": ts, "ecs": {"version": "8.11.0"},
           "message": f"[{severity.upper()}] {name}: {message}",
           "event": {"id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"edr/{rule_id}/{ts}/{pid}")), "kind": "alert",
                     "category": ["process" if rule_id.startswith("EDR-PT") else "file", "intrusion_detection"],
                     "type": ["indicator"], "module": "edr_canary", "dataset": "edr_canary.alerts",
                     "severity": score, "risk_score": float(score), "reason": message,
                     "provider": "Microsoft-Windows-Kernel-ETW"},
           "rule": {"id": rule_id, "name": name, "ruleset": "edr-canary"},
           "threat": {"framework": "MITRE ATT&CK", "technique": {"id": mitre}},
           "host": {"hostname": "ws01", "name": "ws01"}, "process": {"pid": pid, "name": image},
           "tags": ["edr", "etw"]}
    if cmd:
        doc["process"]["command_line"] = cmd
    if parent:
        doc["process"]["parent"] = {"name": parent[0], "pid": parent[1]}
    if file:
        doc["file"] = {"path": file}
    if ancestry:
        doc["edr"] = {"ancestry": ancestry, "depth": len(ancestry.split(" > ")) - 1, "markers": ["-enc", "-w hidden"]}
    if distinct:
        doc["edr"] = {"distinct_files": distinct}
    return doc


def build_maldoc() -> None:
    sid = "maldoc-to-ransomware"
    fixture = ROOT / "03-edr-canary-process-tree" / "tests" / "fixtures" / "maldoc_ransomware_chain.ndjson"
    events = []
    for line in fixture.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue  # the fixture deliberately contains a malformed line
        mapped = map_record("edr-raw", rec, host="ws01", scenario=sid)
        if mapped:
            events.append(mapped)
    pt1 = ["T1566.001", "T1204.002", "T1059.001", "T1059.003"]
    enc = "powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"
    alerts = [
        _edr_alert("EDR-PT-001", "Office application spawned a shell or script host", "critical", pt1,
                   "2026-10-26T09:00:12.000Z", 3150, "cmd.exe",
                   "WINWORD.EXE spawned cmd.exe (markers: -enc, -w hidden)",
                   cmd=f"cmd.exe /c {enc}", parent=("WINWORD.EXE", 3100), ancestry="WINWORD.EXE > cmd.exe"),
        _edr_alert("EDR-PT-001", "Office application spawned a shell or script host", "critical", pt1,
                   "2026-10-26T09:00:12.500Z", 3160, "powershell.exe",
                   "WINWORD.EXE ancestor of powershell.exe at depth 2 (markers: -enc, -w hidden)",
                   cmd=enc, parent=("cmd.exe", 3150), ancestry="WINWORD.EXE > cmd.exe > powershell.exe"),
        _edr_alert("EDR-PT-002", "Office application spawned a living-off-the-land binary", "high",
                   ["T1566.001", "T1218", "T1105"], "2026-10-26T09:00:13.000Z", 3170, "rundll32.exe",
                   "WINWORD.EXE spawned rundll32.exe", cmd="rundll32.exe C:\\Users\\Public\\x.dll,Start",
                   parent=("WINWORD.EXE", 3100)),
        _edr_alert("EDR-RW-001", "Mass file modification (possible encryption)", "critical", ["T1486"],
                   "2026-10-26T09:00:23.400Z", 4100, "svch0st.exe",
                   "PID 4100 modified 25 distinct files in 10 s",
                   file="\\Device\\HarddiskVolume3\\Share\\Finance\\report_24.xlsx", distinct=25),
        _edr_alert("EDR-CN-001", "Canary file tampered", "critical", ["T1486", "T1485"],
                   "2026-10-26T09:00:26.000Z", 4100, "svch0st.exe",
                   "DiskWrite on canary 0_passwords.docx by svch0st.exe (PID 4100)",
                   file="\\Device\\HarddiskVolume3\\Share\\Finance\\0_passwords.docx"),
    ]
    for a in alerts:
        events.append(map_record("edr", a, scenario=sid))
    events += run_soar(alerts[-1], ocsf.to_epoch_ms(alerts[-1]["@timestamp"]) / 1000, 95, sid)
    write(OUT / sid, events)


if __name__ == "__main__":
    build_ssh()
    build_maldoc()
