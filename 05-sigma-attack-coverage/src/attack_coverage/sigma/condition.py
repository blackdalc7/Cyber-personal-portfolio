"""Sigma condition expressions → an AST, by recursive descent.

Grammar (Sigma specification 2.0, condition section)::

    expr    := term ("or" term)*
    term    := factor ("and" factor)*
    factor  := "not" factor | "(" expr ")" | quant | IDENT
    quant   := ("1" | "all" | "any") "of" (IDENT_PATTERN | "them")

``not`` binds tighter than ``and``, which binds tighter than ``or``. Identifier patterns
may use ``*`` (``1 of selection_*``). The deprecated ``|`` aggregation syntax and
``near`` are refused with a clear error rather than silently ignored.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+|\S)")


class ConditionError(ValueError):
    """Raised when a Sigma condition string cannot be parsed."""


@dataclass(frozen=True)
class Ref:
    """Reference to a named selection."""
    name: str


@dataclass(frozen=True)
class Not:
    """Logical negation of one operand."""
    operand: object


@dataclass(frozen=True)
class And:
    """True when every operand is true."""
    operands: tuple


@dataclass(frozen=True)
class Or:
    """True when any operand is true."""
    operands: tuple


@dataclass(frozen=True)
class OfPattern:
    """``1 of <pattern>`` or ``all of <pattern>``, where the pattern globs selection names."""
    quantifier: str   # "1" or "all"
    pattern: str      # identifier glob, or "them"


def _tokens(text: str) -> list[str]:
    toks = [m.group(1) for m in _TOKEN.finditer(text)]
    for t in toks:
        if t == "|":
            raise ConditionError("aggregation expressions ('| count() ...') are not supported; "
                                 "use Sigma correlation rules")
        if not re.fullmatch(r"\(|\)|[A-Za-z0-9_*]+", t):
            raise ConditionError(f"unexpected token {t!r} in condition")
    return toks


def parse_condition(text: str, identifiers: Iterable[str]) -> object:
    """Parse a Sigma condition into an AST of Ref, Not, And, Or and OfPattern nodes.

    Precedence, from tightest: ``not``, ``and``, ``or``. Parentheses group.

    Raises:
        ConditionError: on syntax errors or references to unknown selections.
    """
    known = set(identifiers)
    toks = _tokens(text)
    pos = 0

    def peek() -> str | None:
        """Return the next token, lower-cased, without consuming it."""
        return toks[pos].lower() if pos < len(toks) else None

    def take() -> str:
        """Consume and return the next token."""
        nonlocal pos
        if pos >= len(toks):
            raise ConditionError(f"unexpected end of condition: {text!r}")
        pos += 1
        return toks[pos - 1]

    def expr() -> object:
        """Parse ``term ('or' term)*``."""
        items = [term()]
        while peek() == "or":
            take()
            items.append(term())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def term() -> object:
        """Parse ``factor ('and' factor)*``."""
        items = [factor()]
        while peek() == "and":
            take()
            items.append(factor())
        return items[0] if len(items) == 1 else And(tuple(items))

    def factor() -> object:
        """Parse ``not`` factor, a parenthesised expression, an ``of`` pattern or a selection name."""
        tok = peek()
        if tok == "not":
            take()
            return Not(factor())
        if tok == "(":
            take()
            node = expr()
            if peek() != ")":
                raise ConditionError(f"missing ')' in condition: {text!r}")
            take()
            return node
        if tok in ("1", "all", "any") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            quant = "1" if take().lower() in ("1", "any") else "all"
            take()
            pattern = take()
            if pattern.lower() != "them" and not any(fnmatch.fnmatchcase(k, pattern) for k in known):
                raise ConditionError(f"'{pattern}' matches no detection identifier")
            return OfPattern(quant, "them" if pattern.lower() == "them" else pattern)
        if tok is None:
            raise ConditionError(f"unexpected end of condition: {text!r}")
        if tok in ("and", "or", ")", "of", "near"):
            raise ConditionError(f"unexpected {tok!r} in condition: {text!r}")
        name = take()
        if name not in known:
            raise ConditionError(f"condition references unknown identifier '{name}'")
        return Ref(name)

    node = expr()
    if pos != len(toks):
        raise ConditionError(f"trailing tokens in condition: {' '.join(toks[pos:])!r}")
    return node


def evaluate(node: object, resolve: Callable[[str], bool], identifiers: Iterable[str]) -> bool:
    """Evaluate a condition AST, calling ``resolve(name)`` to test each selection."""
    idents = list(identifiers)
    if isinstance(node, Ref):
        return resolve(node.name)
    if isinstance(node, Not):
        return not evaluate(node.operand, resolve, idents)
    if isinstance(node, And):
        return all(evaluate(n, resolve, idents) for n in node.operands)
    if isinstance(node, Or):
        return any(evaluate(n, resolve, idents) for n in node.operands)
    if isinstance(node, OfPattern):
        # "them" excludes identifiers starting with "_" (Sigma convention for helper selections)
        names = ([i for i in idents if not i.startswith("_")] if node.pattern == "them"
                 else [i for i in idents if fnmatch.fnmatchcase(i, node.pattern)])
        results = (resolve(n) for n in names)
        return all(results) if node.quantifier == "all" else any(results)
    raise ConditionError(f"unknown node {node!r}")
