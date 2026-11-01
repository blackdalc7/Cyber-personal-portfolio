"""Executor that records the commands it would run and runs none of them."""

from __future__ import annotations

from ..campaign import AtomicTest, Target
from .base import ExecResult, now_ms
from .powershell import build_invoke


class DryRunExecutor:
    """Prints what would run and executes nothing. Results are scored ``skipped``."""

    def __init__(self) -> None:
        self.commands: list[str] = []

    def run(self, test: AtomicTest, target: Target) -> ExecResult:
        script = build_invoke(test, atomics_path=target.atomics_path)
        self.commands.append(f"[{target.name}/{target.executor}] {script}")
        t = now_ms()
        return ExecResult(t, t, 0, command=script, executed=False)

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None:
        return None

    def close(self) -> None:
        return None
