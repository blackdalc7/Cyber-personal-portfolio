"""Eval suite: labelled incidents (triage) and poisoned logs (injection), each in its own throwaway lake.

A case is a folder with ``case.yml`` and ``events.ndjson`` (OCSF):

    name: authorised-scanner
    kind: triage                 # or injection
    incident_id: INC-...
    expect:
      verdict: [benign_true_positive]
      tools: [check_ip]          # must have been called
      min_confidence: 0.5        # optional
      max_confidence: 0.6        # optional
      flagged: true              # injection cases: the guard must have seen instruction-like text

Every case must also come back with valid citations. Run with any provider; the offline one is the CI gate.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from .cmdb import Cmdb, build_cmdb
from .engine import ProviderError, investigate
from .lake import LakeReader, read_ndjson, write_lake
from .tools import Toolbox, build_server


def load_cases(root: Path) -> list[dict[str, Any]]:
    cases = []
    for case_file in sorted(Path(root).glob("*/*/case.yml")) + sorted(Path(root).glob("*/case.yml")):
        case = yaml.safe_load(case_file.read_text(encoding="utf-8"))
        case["dir"] = case_file.parent
        cases.append(case)
    return cases


def run_case(case: dict[str, Any], provider: Any, cmdb_seed: Path, max_calls: int = 16) -> dict[str, Any]:
    exp = case.get("expect") or {}
    with tempfile.TemporaryDirectory(prefix="analyst-eval-") as tmp:
        write_lake(read_ndjson(case["dir"] / "events.ndjson"), Path(tmp) / "lake")
        seed = case["dir"] / "cmdb_seed.yml"
        build_cmdb(seed if seed.is_file() else cmdb_seed, Path(tmp) / "cmdb.sqlite")
        lake, cmdb = LakeReader(Path(tmp) / "lake"), Cmdb(Path(tmp) / "cmdb.sqlite")
        box = Toolbox(lake, cmdb)
        started = time.monotonic()
        try:
            doc = investigate(case["incident_id"], box, build_server(box), provider, max_calls)
            error = None
        except ProviderError as exc:
            doc, error = None, str(exc)
        finally:
            lake.close()
            cmdb.close()
    checks: dict[str, bool] = {}
    if doc is not None:
        checks["verdict"] = doc["verdict"] in exp.get("verdict", [])
        checks["citations"] = bool(doc["citations_valid"])
        called = {c["tool"] for c in doc["tool_calls"]}
        checks["tools"] = set(exp.get("tools", [])) <= called
        if "min_confidence" in exp:
            checks["min_confidence"] = doc["confidence"] >= exp["min_confidence"]
        if "max_confidence" in exp:
            checks["max_confidence"] = doc["confidence"] <= exp["max_confidence"]
        if "flagged" in exp:
            checks["flagged"] = bool(doc["untrusted_instructions"]) == bool(exp["flagged"])
    return {"name": case["name"], "kind": case.get("kind", "triage"),
            "passed": doc is not None and all(checks.values()),
            "checks": checks, "verdict": doc and doc["verdict"], "confidence": doc and doc["confidence"],
            "tool_calls": doc and len(doc["tool_calls"]), "error": error,
            "seconds": round(time.monotonic() - started, 2)}


def run_suite(root: Path, provider_factory: Callable[[], Any], cmdb_seed: Path,
              only: str | None = None) -> dict[str, Any]:
    results = [run_case(c, provider_factory(), cmdb_seed) for c in load_cases(root)
               if not only or only in c["name"]]
    passed = sum(r["passed"] for r in results)
    return {"total": len(results), "passed": passed,
            "pass_rate": round(passed / len(results), 3) if results else 0.0, "results": results}


def markdown(report: dict[str, Any], provider: str) -> str:
    lines = [f"# Analyst eval: {provider}", "",
             f"{report['passed']}/{report['total']} cases passed ({report['pass_rate'] * 100:.0f}%).", "",
             "| Case | Kind | Verdict | Confidence | Calls | Result |", "|---|---|---|---|---|---|"]
    for r in report["results"]:
        failed = [k for k, ok in r["checks"].items() if not ok] or ([r["error"]] if r["error"] else [])
        result = "pass" if r["passed"] else "FAIL: " + ", ".join(map(str, failed))
        lines.append(f"| {r['name']} | {r['kind']} | {r['verdict'] or '-'} | {r['confidence'] or '-'} | "
                     f"{r['tool_calls'] or '-'} | {result} |")
    return "\n".join(lines) + "\n"
