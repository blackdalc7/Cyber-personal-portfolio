"""Rebuild ``tests/fixtures/replay/*.ndjson`` from raw sensor records, through Watchfloor's own mappers.

Each fixture is what one Atomic test looks like to the platform in the lab: Tetragon export lines from lab-k8s or
Sysmon records from lab-win01 (as Fluent Bit ships them), mapped to OCSF exactly as ``/api/ingest/tetragon`` and
``/api/ingest/winlog`` would map them, plus a little background noise from the same host. Committing the mapped
OCSF keeps the replay executor independent of Watchfloor; this script keeps the fixtures honest.

    python scripts/build_fixtures.py            # needs ../watchfloor/backend/src importable (see README)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT.parent / "watchfloor" / "backend" / "src"))

from watchfloor.mappers import map_record  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "replay"
T0 = datetime(2026, 10, 1, 9, 0, 0, tzinfo=timezone.utc)
POD = {"namespace": "atomic", "name": "atomic-runner-7c9f6d5b8-x2kqp",
       "container": {"name": "runner", "image": {"name": "localhost:32000/atomic-runner:1.0.0"}}}
_exec_ids = iter(range(1000, 100000))


def iso(ms: int) -> str:
    return (T0 + timedelta(milliseconds=ms)).isoformat().replace("+00:00", "Z")


def tg_proc(binary: str, args: str, pid: int, uid: int = 0) -> dict[str, Any]:
    return {"binary": binary, "arguments": args, "pid": pid, "uid": uid, "pod": POD,
            "exec_id": f"bGFiLWs4czo{next(_exec_ids)}"}


PWSH = tg_proc("/usr/bin/pwsh", "-NoProfile -NonInteractive -EncodedCommand <redacted>", 41)


def tg_exec(ms: int, binary: str, args: str, pid: int, parent: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"process_exec": {"process": tg_proc(binary, args, pid), "parent": parent or PWSH},
            "node_name": "lab-k8s", "time": iso(ms)}


def tg_file(ms: int, binary: str, args: str, pid: int, path: str, *, write: bool = False) -> dict[str, Any]:
    func = "security_file_permission"
    return {"process_kprobe": {"process": tg_proc(binary, args, pid), "parent": PWSH, "function_name": func,
                               "policy_name": "file-credential-access",
                               "args": [{"file_arg": {"path": path}}, {"int_arg": 2 if write else 4}],
                               "action": "KPROBE_ACTION_POST"},
            "node_name": "lab-k8s", "time": iso(ms)}


def tg_connect(ms: int, pid: int, dst: str, port: int) -> dict[str, Any]:
    return {"process_kprobe": {"process": tg_proc("/usr/bin/bash", "-c <port scan loop>", pid), "parent": PWSH,
                               "function_name": "tcp_connect", "policy_name": "network-connect",
                               "args": [{"sock_arg": {"family": "AF_INET", "protocol": "TCP", "saddr": "10.1.80.23",
                                                      "sport": 40000 + port, "daddr": dst, "dport": port}}],
                               "action": "KPROBE_ACTION_POST"},
            "node_name": "lab-k8s", "time": iso(ms)}


def k8s_noise(ms: int) -> list[dict[str, Any]]:
    kubelet = tg_proc("/snap/microk8s/current/kubelite", "--kubelet-args-file=...", 900)
    return [tg_exec(ms, "/usr/bin/runc", "--root /run/containerd/runc/k8s.io state 5f1c", 3100 + ms // 100, kubelet),
            tg_exec(ms + 400, "/usr/sbin/iptables", "-w -t nat -S KUBE-SERVICES", 3200 + ms // 100, kubelet)]


_record_ids = iter(range(5000, 100000))


def sysmon(ms: int, eid: int, fields: dict[str, Any]) -> dict[str, Any]:
    message = {1: "Process Create:", 3: "Network connection detected:", 11: "File created:"}[eid]
    body = "\n".join([message, f"UtcTime: {iso(ms)}", *(f"{k}: {v}" for k, v in fields.items())])
    return {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": eid, "Computer": "lab-win01",
            "TimeCreated": iso(ms), "EventRecordID": next(_record_ids), "Message": body}


def proc_create(ms: int, image: str, cmd: str, pid: int, parent_image: str, parent_cmd: str, ppid: int,
                user: str = "LAB-WIN01\\vagrant") -> dict[str, Any]:
    return sysmon(ms, 1, {"ProcessId": pid, "Image": image, "CommandLine": cmd, "User": user,
                          "ParentProcessId": ppid, "ParentImage": parent_image, "ParentCommandLine": parent_cmd})


WSMPROV = "C:\\Windows\\System32\\wsmprovhost.exe"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def win_noise(ms: int) -> list[dict[str, Any]]:
    return [proc_create(ms, "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                        7100, "C:\\Windows\\System32\\services.exe", "C:\\Windows\\system32\\services.exe", 720,
                        "NT AUTHORITY\\SYSTEM"),
            proc_create(ms + 600, "C:\\Windows\\System32\\conhost.exe",
                        "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", 7120,
                        WSMPROV, "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", 5400)]


FIXTURES: dict[str, tuple[str, list[dict[str, Any]]]] = {
    # ---------------------------------------------------------------- lab-k8s (Tetragon)
    "T1003.008": ("tetragon", [
        *k8s_noise(0),
        tg_exec(1000, "/bin/sh", "-c \"sudo cat /etc/shadow\"", 101),
        tg_exec(1010, "/usr/bin/cat", "/etc/shadow", 102),
        tg_file(1015, "/usr/bin/cat", "/etc/shadow", 102, "/etc/shadow"),
    ]),
    "T1136.001": ("tetragon", [
        *k8s_noise(0),
        tg_exec(1000, "/bin/sh", "-c \"useradd -M -N -r -s /bin/bash -c evil_account art\"", 201),
        tg_exec(1010, "/usr/sbin/useradd", "-M -N -r -s /bin/bash -c evil_account art", 202),
        tg_file(1020, "/usr/sbin/useradd", "-M -N -r -s /bin/bash -c evil_account art", 202, "/etc/passwd",
                write=True),
        tg_file(1025, "/usr/sbin/useradd", "-M -N -r -s /bin/bash -c evil_account art", 202, "/etc/shadow",
                write=True),
    ]),
    "T1053.003": ("tetragon", [
        *k8s_noise(0),
        tg_exec(1000, "/bin/sh", "-c \"crontab -l > /tmp/notevil; echo '* * * * * /tmp/evil.sh' > /tmp/persistevil "
                "&& crontab /tmp/persistevil\"", 301),
        tg_exec(1010, "/usr/bin/crontab", "-l", 302),
        tg_exec(1030, "/usr/bin/crontab", "/tmp/persistevil", 303),
        tg_file(1035, "/usr/bin/crontab", "/tmp/persistevil", 303, "/var/spool/cron/crontabs/root", write=True),
    ]),
    "T1070.003": ("tetragon", [
        *k8s_noise(0),
        tg_exec(1000, "/bin/sh", "-c \"rm ~/.bash_history\"", 401),
        tg_exec(1010, "/usr/bin/rm", "/root/.bash_history", 402),
    ]),
    "T1046": ("tetragon", [
        *k8s_noise(0),
        tg_exec(1000, "/usr/bin/bash", "-c <port scan loop>", 501),
        *(tg_connect(1100 + i * 20, 501, "10.1.80.1", port)
          for i, port in enumerate((21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5985, 8080))),
    ]),
    # ---------------------------------------------------------------- lab-win01 (Sysmon via Fluent Bit)
    "T1059.001": ("winlog", [
        *win_noise(0),
        proc_create(1000, PS, "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA=",
                    6100, WSMPROV, "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", 5400),
        proc_create(1500, PS, "powershell.exe -NoProfile -ec VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA=",
                    6110, WSMPROV, "C:\\Windows\\system32\\wsmprovhost.exe -Embedding", 5400),
    ]),
    "T1036.003": ("winlog", [
        *win_noise(0),
        proc_create(1000, "C:\\Windows\\System32\\cmd.exe",
                    "cmd.exe /c copy %SystemRoot%\\System32\\cmd.exe %SystemRoot%\\Temp\\lsass.exe & "
                    "%SystemRoot%\\Temp\\lsass.exe /B", 6200, PS, "powershell.exe -NoProfile", 6150),
        sysmon(1100, 11, {"ProcessId": 6200, "Image": "C:\\Windows\\System32\\cmd.exe",
                          "TargetFilename": "C:\\Windows\\Temp\\lsass.exe"}),
        proc_create(1200, "C:\\Windows\\Temp\\lsass.exe", "C:\\Windows\\Temp\\lsass.exe /B", 6210,
                    "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c copy ...", 6200),
    ]),
    "T1087.001": ("winlog", [
        *win_noise(0),
        proc_create(1000, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user & dir c:\\Users\\ & "
                    "cmdkey.exe /list", 6300, PS, "powershell.exe -NoProfile", 6150),
        proc_create(1050, "C:\\Windows\\System32\\net.exe", "net user", 6310,
                    "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user", 6300),
        proc_create(1300, "C:\\Windows\\System32\\cmdkey.exe", "cmdkey.exe /list", 6320,
                    "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c net user", 6300),
    ]),
    # Once the Sysmon filter driver is unloaded the host goes quiet: this is what "missed" looks like.
    "T1562.001": ("winlog", []),
}


def build(name: str, source: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for rec in records:
        doc = map_record(source, rec)
        if doc is None:
            raise SystemExit(f"{name}: a {source} record did not map: {json.dumps(rec)[:200]}")
        out.append(doc)
    return sorted(out, key=lambda d: d["time"])


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, (source, records) in FIXTURES.items():
        docs = build(name, source, records)
        (OUT / f"{name}.ndjson").write_text(
            "".join(json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n" for d in docs), encoding="utf-8")
        print(f"{name}: {len(docs)} events ({source})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
