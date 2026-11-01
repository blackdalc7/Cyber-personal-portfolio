from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ..campaign import AtomicTest, Target
from .base import ExecResult, is_prevented, now_ms
from .powershell import build_invoke, encode_ps

Runner = Callable[..., Any]


class KubectlExecutor:
    """Runs atomics inside the lab's Atomic runner pod with ``kubectl exec`` (argv only, no shell)."""

    def __init__(self, runner: Runner = subprocess.run) -> None:
        self._run = runner

    def _exec(self, script: str, target: Target, timeout: int) -> ExecResult:
        argv = ["kubectl", "--context", target.kube_context or "", "-n", target.namespace, "exec", target.workload,
                "--", "pwsh", "-NoProfile", "-NonInteractive", "-EncodedCommand", encode_ps(script)]
        start = now_ms()
        try:
            out = self._run(argv, capture_output=True, text=True, timeout=timeout + 30, check=False)
        except subprocess.TimeoutExpired:
            return ExecResult(start, now_ms(), 124, command=script, error="timed out")
        except FileNotFoundError:
            return ExecResult(start, now_ms(), 127, command=script, error="kubectl not found", executed=False)
        return ExecResult(start, now_ms(), out.returncode, out.stdout or "", out.stderr or "", script,
                          prevented=is_prevented(out.returncode, out.stdout or "", out.stderr or ""))

    def run(self, test: AtomicTest, target: Target) -> ExecResult:
        if test.get_prereqs:
            self._exec(build_invoke(test, prereqs=True, atomics_path=target.atomics_path), target, test.timeout_s)
        return self._exec(build_invoke(test, atomics_path=target.atomics_path), target, test.timeout_s)

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None:
        return self._exec(build_invoke(test, cleanup=True, atomics_path=target.atomics_path), target, test.timeout_s)

    def close(self) -> None:
        return None
