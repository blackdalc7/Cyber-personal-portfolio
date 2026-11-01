"""Load Sigma rules from disk and compile each one to a DuckDB query."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from .backend import DuckDBBackend, pretty

LEVEL_SEVERITY = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_TECHNIQUE_TAG = re.compile(r"^t\d{4}(\.\d{3})?$")


class RuleError(ValueError):
    """A rule file could not be parsed or compiled."""


@dataclass(frozen=True)
class CompiledRule:
    id: str
    title: str
    status: str
    level: str
    description: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    logsource: str
    path: str
    sql: str
    tuned_from: str | None = None

    @property
    def severity_id(self) -> int:
        return LEVEL_SEVERITY.get(self.level, 3)

    @property
    def stem(self) -> str:
        return Path(self.path).stem


def _enum_name(value: Any, default: str) -> str:
    return str(getattr(value, "name", value) or default).lower()


def compile_file(path: Path, root: Path, backend: DuckDBBackend | None = None) -> CompiledRule:
    backend = backend or DuckDBBackend()
    text = Path(path).read_text(encoding="utf-8")
    try:
        collection = SigmaCollection.from_yaml(text)
        queries = backend.convert(collection)
    except SigmaError as exc:
        raise RuleError(f"{path}: {exc}") from exc
    if len(collection.rules) != 1 or len(queries) != 1:
        raise RuleError(f"{path}: one rule per file, please")
    rule = collection.rules[0]
    if rule.id is None:
        raise RuleError(f"{path}: every rule needs an id (a UUID), findings are keyed on it")
    tags = [f"{t.namespace}.{t.name}" for t in rule.tags]
    techniques = tuple(sorted({t.split(".", 1)[1].upper() for t in tags
                               if t.startswith("attack.") and _TECHNIQUE_TAG.match(t.split(".", 1)[1])}))
    tactics = tuple(t.split(".", 1)[1] for t in tags
                    if t.startswith("attack.") and not _TECHNIQUE_TAG.match(t.split(".", 1)[1])
                    and not re.match(r"^[gs]\d{4}$", t.split(".", 1)[1]))
    ls = rule.logsource
    custom = getattr(rule, "custom_attributes", {}) or {}
    tuned = custom.get("tuned_from")
    return CompiledRule(
        id=str(rule.id), title=rule.title, status=_enum_name(rule.status, "experimental"),
        level=_enum_name(rule.level, "medium"), description=" ".join((rule.description or "").split()),
        techniques=techniques, tactics=tactics, logsource=":".join(x for x in (ls.product, ls.category) if x),
        path=Path(path).resolve().relative_to(Path(root).resolve().parent).as_posix(), sql=pretty(queries[0]),
        tuned_from=" ".join(str(tuned).split()) if tuned else None,
    )


def load_rules(rules_dir: Path) -> list[CompiledRule]:
    rules_dir = Path(rules_dir)
    files = sorted(rules_dir.rglob("*.yml"))
    if not files:
        raise RuleError(f"no rules under {rules_dir}")
    backend = DuckDBBackend()
    out = [compile_file(p, rules_dir, backend) for p in files]
    ids = [r.id for r in out]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"duplicate rule ids: {', '.join(sorted(dupes))}")
    return out
