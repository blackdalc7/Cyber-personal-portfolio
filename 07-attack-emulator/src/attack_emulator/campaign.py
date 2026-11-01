"""Campaign files: which Atomic tests to run, on which lab target, and how to reach it.

```yaml
name: Linux credential access
settle_s: 20
targets:
  - {name: k8s, executor: kubectl, hostname: lab-k8s, kube_context: microk8s, namespace: atomic}
tests:
  - {technique: T1003.008, name: Read /etc/shadow, tactic: credential-access, target: k8s,
     test_names: ["Access /etc/shadow (Local)"], telemetry_match: shadow}
```
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

EXECUTORS = ("winrm", "ssh", "kubectl", "replay", "dry-run")
LIVE_EXECUTORS = ("winrm", "ssh", "kubectl")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


class CampaignError(ValueError):
    """The campaign file is invalid."""


@dataclass(frozen=True)
class Target:
    name: str
    executor: str
    hostname: str
    address: str | None = None
    kube_context: str | None = None
    namespace: str = "atomic"
    workload: str = "deploy/atomic-runner"
    atomics_path: str | None = None


@dataclass(frozen=True)
class AtomicTest:
    technique: str
    name: str
    tactic: str
    target: str
    test_numbers: tuple[int, ...] = ()
    test_guids: tuple[str, ...] = ()
    input_args: dict[str, str | int | bool] = field(default_factory=dict)
    timeout_s: int = 120
    get_prereqs: bool = False
    cleanup: bool = True
    test_names: tuple[str, ...] = ()
    telemetry_match: str | None = None

    @property
    def key(self) -> str:
        sel = (",".join(map(str, self.test_numbers)) or ",".join(g[:8] for g in self.test_guids)
               or ",".join(self.test_names) or "all")
        return f"{self.technique}#{sel}"


@dataclass(frozen=True)
class Campaign:
    name: str
    description: str
    targets: dict[str, Target]
    tests: tuple[AtomicTest, ...]
    settle_s: float = 15

    @property
    def live(self) -> bool:
        return any(t.executor in LIVE_EXECUTORS for t in self.targets.values())


def _str(d: dict[str, Any], key: str, where: str, default: str | None = None) -> str:
    value = d.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise CampaignError(f"{where}: '{key}' must be a non-empty string")
    return value.strip()


def _arg_value(name: str, value: Any, where: str) -> str | int | bool:
    if isinstance(value, bool | int):
        return value
    if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise CampaignError(f"{where}: input arg {name!r} must be a short single-line string, int or bool")
    return value


def _target(raw: Any, i: int) -> Target:
    where = f"targets[{i}]"
    if not isinstance(raw, dict):
        raise CampaignError(f"{where} must be a mapping")
    name = _str(raw, "name", where)
    if not SAFE_NAME.match(name):
        raise CampaignError(f"{where}: name {name!r} must be a simple identifier")
    executor = _str(raw, "executor", where)
    if executor not in EXECUTORS:
        raise CampaignError(f"{where}: executor must be one of {', '.join(EXECUTORS)}")
    hostname = _str(raw, "hostname", where)
    if not HOSTNAME.match(hostname):
        raise CampaignError(f"{where}: hostname {hostname!r} is not a valid host name")
    address = raw.get("address")
    if executor in ("winrm", "ssh") and not address:
        raise CampaignError(f"{where}: {executor} targets need an 'address' (an IP inside LAB_ALLOWED_CIDRS)")
    ctx = raw.get("kube_context")
    if executor == "kubectl" and not ctx:
        raise CampaignError(f"{where}: kubectl targets need 'kube_context'")
    namespace = str(raw.get("namespace", "atomic"))
    workload = str(raw.get("workload", "deploy/atomic-runner"))
    for label, value in (("namespace", namespace), ("workload", workload.replace("/", "-"))):
        if not SAFE_NAME.match(value):
            raise CampaignError(f"{where}: {label} {value!r} is not a valid Kubernetes name")
    atomics = raw.get("atomics_path")
    if atomics is not None and (not isinstance(atomics, str) or "'" in atomics or len(atomics) > 200):
        raise CampaignError(f"{where}: atomics_path must be a plain path without quotes")
    return Target(name=name, executor=executor, hostname=hostname, address=str(address) if address else None,
                  kube_context=str(ctx) if ctx else None, namespace=namespace, workload=workload,
                  atomics_path=atomics)


def _test(raw: Any, i: int, targets: dict[str, Target]) -> AtomicTest:
    where = f"tests[{i}]"
    if not isinstance(raw, dict):
        raise CampaignError(f"{where} must be a mapping")
    technique = _str(raw, "technique", where).upper()
    if not TECHNIQUE.match(technique):
        raise CampaignError(f"{where}: technique {technique!r} must look like T1059 or T1059.001")
    target = _str(raw, "target", where)
    if target not in targets:
        raise CampaignError(f"{where}: unknown target {target!r}")
    numbers = raw.get("test_numbers", []) or []
    if not isinstance(numbers, list) or not all(isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= 999
                                                for n in numbers):
        raise CampaignError(f"{where}: test_numbers must be a list of integers 1-999")
    guids = raw.get("test_guids", []) or []
    if not isinstance(guids, list) or not all(isinstance(g, str) and GUID.match(g) for g in guids):
        raise CampaignError(f"{where}: test_guids must be a list of GUIDs")
    names = raw.get("test_names", []) or []
    if not isinstance(names, list) or not all(isinstance(n, str) and 0 < len(n) <= 200 and n.isprintable()
                                              for n in names):
        raise CampaignError(f"{where}: test_names must be a list of single-line test names")
    if not numbers and not guids and not names:
        raise CampaignError(f"{where}: pick tests explicitly with test_names, test_numbers or test_guids "
                            "(never 'all')")
    match = raw.get("telemetry_match")
    if match is not None and (not isinstance(match, str) or not 0 < len(match) <= 100 or not match.isprintable()):
        raise CampaignError(f"{where}: telemetry_match must be a short single-line string")
    args = raw.get("input_args", {}) or {}
    if not isinstance(args, dict):
        raise CampaignError(f"{where}: input_args must be a mapping")
    for k in args:
        if not isinstance(k, str) or not ARG_NAME.match(k):
            raise CampaignError(f"{where}: input arg name {k!r} is not a valid identifier")
    timeout = raw.get("timeout_s", 120)
    if not isinstance(timeout, int) or not 5 <= timeout <= 1800:
        raise CampaignError(f"{where}: timeout_s must be an integer between 5 and 1800")
    return AtomicTest(
        technique=technique, name=_str(raw, "name", where, technique), tactic=str(raw.get("tactic", "unknown")),
        target=target, test_numbers=tuple(numbers), test_guids=tuple(guids),
        input_args={k: _arg_value(k, v, where) for k, v in args.items()}, timeout_s=timeout,
        get_prereqs=bool(raw.get("get_prereqs", False)), cleanup=bool(raw.get("cleanup", True)),
        test_names=tuple(names), telemetry_match=match,
    )


def parse_campaign(doc: Any) -> Campaign:
    if not isinstance(doc, dict):
        raise CampaignError("campaign must be a mapping")
    name = _str(doc, "name", "campaign")
    raw_targets = doc.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise CampaignError("campaign: 'targets' must be a non-empty list")
    targets: dict[str, Target] = {}
    for i, raw in enumerate(raw_targets):
        t = _target(raw, i)
        if t.name in targets:
            raise CampaignError(f"targets[{i}]: duplicate name {t.name!r}")
        targets[t.name] = t
    raw_tests = doc.get("tests")
    if not isinstance(raw_tests, list) or not raw_tests:
        raise CampaignError("campaign: 'tests' must be a non-empty list")
    settle = doc.get("settle_s", 15)
    if not isinstance(settle, int | float) or settle < 0 or settle > 600:
        raise CampaignError("campaign: settle_s must be between 0 and 600 seconds")
    return Campaign(name=name, description=str(doc.get("description", "")), targets=targets,
                    tests=tuple(_test(raw, i, targets) for i, raw in enumerate(raw_tests)), settle_s=float(settle))


def load_campaign(path: Path) -> Campaign:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CampaignError(f"cannot read {path}: {exc}") from exc
    return parse_campaign(doc)
