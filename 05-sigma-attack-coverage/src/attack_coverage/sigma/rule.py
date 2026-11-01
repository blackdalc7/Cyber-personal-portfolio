"""Sigma rule loading, schema validation and compilation into match functions.

Supported (covers the large majority of SigmaHQ process-creation rules):

* selections as maps (AND across fields), lists of maps (OR) and keyword lists
* value lists (OR) and the ``|all`` modifier (AND)
* wildcards ``*`` / ``?`` with ``\\`` escaping; case-insensitive matching by default
* modifiers: contains, startswith, endswith, all, re, windash, cidr, exists, cased,
  gt, gte, lt, lte, fieldref
* ``null`` values (field absent or empty)

Encoding modifiers (base64, base64offset, utf16le, utf16be, wide) and correlation
rules raise :class:`SigmaRuleError`, so an unsupported rule fails loudly at load time
instead of silently never matching.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .condition import ConditionError, evaluate, parse_condition

STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
SUPPORTED = {"contains", "startswith", "endswith", "all", "re", "windash", "cidr", "exists", "cased",
             "gt", "gte", "lt", "lte", "fieldref"}
UNSUPPORTED = {"base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "expand"}
_TAG = re.compile(r"^[a-z0-9_.-]+$")
_ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
_DATE = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}$")
DASHES = ("-", "/", "–", "—", "―")

Event = Mapping[str, Any]
Matcher = Callable[[Event], bool]


class SigmaRuleError(ValueError):
    """Raised when a Sigma rule is invalid or uses unsupported features."""


def _wildcard_regex(value: str, cased: bool, lead_any: bool = False, trail_any: bool = False) -> re.Pattern[str]:
    # Modifier-added wildcards are applied outside the value, so a trailing backslash in the
    # value ('C:\\Users\\' with startswith) stays a literal backslash, not an escape.
    out, i = [".*"] if lead_any else [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    if trail_any:
        out.append(".*")
    return re.compile("^" + "".join(out) + "$", re.DOTALL | (0 if cased else re.IGNORECASE))


def _windash_variants(value: str) -> list[str]:
    # Replace a dash that starts a word (an option like -enc or -c) with every dash-like prefix.
    if not re.search(r"(^|\s)-", value):
        return [value]
    return [re.sub(r"(^|\s)-", lambda m, d=d: m.group(1) + d, value) for d in DASHES]


def _as_strings(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    if isinstance(v, bool):
        return [str(v).lower()]
    return [str(v)]


def _number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def compile_field(key: str, values: Any) -> Matcher:
    """Compile one ``field|modifier: value(s)`` item into a predicate over events.

    Supports the modifiers in ``SUPPORTED`` (contains, startswith, endswith, re,
    all, exists, cased, windash, cidr, numeric comparisons and fieldref).

    Raises:
        SigmaRuleError: for unsupported modifiers or invalid values.
    """
    parts = key.split("|")
    fname, mods = parts[0], [m.lower() for m in parts[1:]]
    bad = [m for m in mods if m in UNSUPPORTED or m not in SUPPORTED | UNSUPPORTED]
    if bad:
        raise SigmaRuleError(f"modifier(s) {bad} on '{key}' are not supported by this engine")
    vals = values if isinstance(values, list) else [values]
    cased = "cased" in mods
    combine = all if "all" in mods else any

    if "exists" in mods:
        want = bool(vals[0])
        return lambda ev: (ev.get(fname) not in (None, "")) == want

    if "fieldref" in mods:
        refs = [str(v) for v in vals]
        return lambda ev: combine(
            any(a.lower() == b.lower() for a in _as_strings(ev.get(fname)) for b in _as_strings(ev.get(r)))
            for r in refs)

    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            limits = [float(v) for v in vals]
            cmp = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[op]

            def numeric(ev: Event, limits=limits, cmp=cmp) -> bool:
                n = _number(ev.get(fname))
                return n is not None and combine(cmp(n, lim) for lim in limits)
            return numeric

    if "cidr" in mods:
        nets = [ipaddress.ip_network(str(v), strict=False) for v in vals]

        def in_cidr(ev: Event) -> bool:
            for s in _as_strings(ev.get(fname)):
                try:
                    ip = ipaddress.ip_address(s)
                except ValueError:
                    continue
                if combine(ip in n for n in nets):
                    return True
            return False
        return in_cidr

    if "re" in mods:
        pats = [re.compile(str(v)) for v in vals]
        return lambda ev: combine(any(p.search(s) for s in _as_strings(ev.get(fname))) for p in pats)

    # A value list is OR by default; with windash each value expands into several, still ORed.
    groups: list[list[re.Pattern[str] | None]] = []
    for v in vals:
        if v is None:
            groups.append([None])
            continue
        text = str(v).lower() if isinstance(v, bool) else str(v)
        variants = _windash_variants(text) if "windash" in mods else [text]
        compiled: list[re.Pattern[str] | None] = []
        lead = "contains" in mods or "endswith" in mods
        trail = "contains" in mods or "startswith" in mods
        compiled.extend(_wildcard_regex(t, cased, lead, trail) for t in variants)
        groups.append(compiled)

    def match(ev: Event) -> bool:
        """True if the event's field matches the compiled values under the modifiers."""
        raw = ev.get(fname)
        strings = _as_strings(raw)

        def one(p: re.Pattern[str] | None) -> bool:
            """Test one compiled pattern; ``None`` stands for a null value in the rule."""
            if p is None:
                return raw is None or raw == "" or raw == []
            return any(p.match(s) for s in strings)
        return combine(any(one(p) for p in g) for g in groups)
    return match


def compile_selection(name: str, body: Any) -> Matcher:
    """Compile a named selection: a field map, a list of field maps, or a keyword list."""
    if isinstance(body, Mapping):
        if not body:
            raise SigmaRuleError(f"selection '{name}' is empty")
        items = [compile_field(str(k), v) for k, v in body.items()]
        return lambda ev: all(m(ev) for m in items)
    if isinstance(body, list) and body and all(isinstance(x, Mapping) for x in body):
        alts = [compile_selection(name, x) for x in body]
        return lambda ev: any(m(ev) for m in alts)
    if isinstance(body, list) and body and all(not isinstance(x, (Mapping, list)) for x in body):
        pats = [_wildcard_regex(str(x), cased=False, lead_any=True, trail_any=True) for x in body]
        return lambda ev: any(p.match(s) for p in pats for v in ev.values() for s in _as_strings(v))
    raise SigmaRuleError(f"selection '{name}' must be a map, a list of maps, or a keyword list")


@dataclass
class SigmaRule:
    """A parsed and compiled Sigma rule, ready to match events."""
    id: str
    title: str
    level: str
    status: str
    logsource: dict[str, str]
    tags: list[str]
    detection: dict[str, Any]
    path: str = ""
    description: str = ""
    falsepositives: list[str] = field(default_factory=list)
    _matchers: dict[str, Matcher] = field(default_factory=dict, repr=False)
    _conditions: list[object] = field(default_factory=list, repr=False)

    @property
    def techniques(self) -> list[str]:
        """ATT&CK technique ids from the rule's ``attack.tXXXX`` tags, upper-cased and sorted."""
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if _ATTACK_TECHNIQUE.match(t)})

    def applies_to(self, event_logsource: Mapping[str, str]) -> bool:
        """True if the event's logsource matches the rule's category, product and service."""
        return all(event_logsource.get(k, "").lower() == v.lower() for k, v in self.logsource.items()
                   if k in ("category", "product", "service"))

    def matches(self, event: Event) -> bool:
        """True if the event satisfies any of the rule's conditions."""
        cache: dict[str, bool] = {}

        def resolve(name: str) -> bool:
            """Evaluate a selection once per event and cache the result."""
            if name not in cache:
                cache[name] = self._matchers[name](event)
            return cache[name]
        return any(evaluate(c, resolve, self._matchers) for c in self._conditions)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], path: str = "") -> SigmaRule:
        """Validate and compile a rule from its parsed YAML.

        Raises:
            SigmaRuleError: for missing fields, a non-UUID id, correlation rules or bad detection logic.
        """
        where = path or str(data.get("title", "rule"))
        if not isinstance(data, Mapping):
            raise SigmaRuleError(f"{where}: a rule must be a YAML mapping")
        if "correlation" in data:
            raise SigmaRuleError(f"{where}: correlation rules are not supported")
        for req in ("title", "id", "logsource", "detection"):
            if req not in data:
                raise SigmaRuleError(f"{where}: missing required field '{req}'")
        try:
            rid = str(uuid.UUID(str(data["id"])))
        except ValueError as exc:
            raise SigmaRuleError(f"{where}: id must be a UUID") from exc
        status = str(data.get("status", "experimental"))
        level = str(data.get("level", "medium"))
        if status not in STATUSES:
            raise SigmaRuleError(f"{where}: status must be one of {sorted(STATUSES)}")
        if level not in LEVELS:
            raise SigmaRuleError(f"{where}: level must be one of {sorted(LEVELS)}")
        if "date" in data and not _DATE.match(str(data["date"])):
            raise SigmaRuleError(f"{where}: date must be YYYY-MM-DD")
        logsource = data["logsource"]
        if not isinstance(logsource, Mapping) or not any(k in logsource for k in ("category", "product", "service")):
            raise SigmaRuleError(f"{where}: logsource needs category, product or service")
        tags = [str(t) for t in data.get("tags") or []]
        bad_tags = [t for t in tags if not _TAG.match(t)]
        if bad_tags:
            raise SigmaRuleError(f"{where}: invalid tags {bad_tags}")
        detection = dict(data["detection"])
        condition = detection.pop("condition", None)
        if condition is None:
            raise SigmaRuleError(f"{where}: detection.condition is required")
        detection.pop("timeframe", None)
        if not detection:
            raise SigmaRuleError(f"{where}: detection has no selections")
        rule = cls(id=rid, title=str(data["title"]), level=level, status=status,
                   logsource={k: str(v) for k, v in logsource.items()}, tags=tags, detection=detection, path=path,
                   description=str(data.get("description", "")),
                   falsepositives=[str(x) for x in data.get("falsepositives") or []])
        try:
            rule._matchers = {name: compile_selection(name, body) for name, body in detection.items()}
        except (re.error, ValueError) as exc:
            raise SigmaRuleError(f"{where}: {exc}") from exc
        conds = condition if isinstance(condition, list) else [condition]
        try:
            rule._conditions = [parse_condition(str(c), rule._matchers) for c in conds]
        except ConditionError as exc:
            raise SigmaRuleError(f"{where}: {exc}") from exc
        return rule


def load_rules(paths: Iterable[str | Path]) -> list[SigmaRule]:
    """Load every Sigma rule from the given files and directories (recursively, .yml and .yaml).

    Raises:
        SigmaRuleError: for an invalid rule or a duplicate rule id.
    """
    rules: list[SigmaRule] = []
    seen: dict[str, str] = {}
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        files.extend(sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml")) if p.is_dir() else [p])
    for f in files:
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if doc is None:
                continue
            rule = SigmaRule.from_dict(doc, f.as_posix())
            if rule.id in seen:
                raise SigmaRuleError(f"duplicate rule id {rule.id} in {f} and {seen[rule.id]}")
            seen[rule.id] = f.as_posix()
            rules.append(rule)
    return rules
