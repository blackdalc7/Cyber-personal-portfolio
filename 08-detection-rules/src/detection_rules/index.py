"""``build/``: the rules index the Watchfloor hub serves at /api/rules, plus one .sql file per rule."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .rules import CompiledRule
from .testing import RuleTestResult


def rule_info(rule: CompiledRule, tests: list[RuleTestResult]) -> dict[str, Any]:
    return {"id": rule.id, "title": rule.title, "status": rule.status, "level": rule.level,
            "techniques": list(rule.techniques), "tactics": list(rule.tactics), "logsource": rule.logsource,
            "tests": [t.as_dict() for t in tests], "path": rule.path, "queries": {"duckdb": rule.sql},
            "tuned_from": rule.tuned_from, "description": rule.description}


def build_index(rules: list[CompiledRule], tests: dict[str, list[RuleTestResult]], *,
                generated: datetime | None = None) -> dict[str, Any]:
    stamp = (generated or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {"generated": stamp, "backend": "duckdb", "pipeline": "Sigma to Watchfloor OCSF 1.4.0",
            "rules": [rule_info(r, tests.get(r.id, [])) for r in rules]}


def write_build(index: dict[str, Any], rules: list[CompiledRule], build_dir: Path) -> Path:
    build_dir = Path(build_dir)
    (build_dir / "queries").mkdir(parents=True, exist_ok=True)
    for r in rules:
        (build_dir / "queries" / f"{r.stem}.sql").write_text(f"-- {r.title}\n-- {r.id}\n{r.sql};\n", encoding="utf-8")
    out = build_dir / "rules_index.json"
    out.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return out
