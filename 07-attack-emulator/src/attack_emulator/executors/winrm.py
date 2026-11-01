"""Executor for Windows lab VMs over WinRM (pywinrm)."""

from __future__ import annotations

from typing import Any

from ..campaign import AtomicTest, Target
from .base import ExecResult, is_prevented, now_ms
from .powershell import build_invoke


class WinRmExecutor:
    """Runs atomics on a Windows lab VM over WinRM (pywinrm encodes the script; nothing is shell-quoted)."""

    def __init__(self, user: str, password: str, transport: str = "ntlm", session_factory: Any = None) -> None:
        if not user or not password:
            raise ValueError("WinRM targets need EMU_WINRM_USER and EMU_WINRM_PASSWORD")
        self._user, self._password, self._transport = user, password, transport
        self._factory = session_factory
        self._sessions: dict[str, Any] = {}

    def _session(self, target: Target) -> Any:
        if target.name not in self._sessions:
            if self._factory is None:
                import winrm  # imported lazily so non-Windows campaigns do not need it

                self._factory = winrm.Session
            self._sessions[target.name] = self._factory(
                f"http://{target.address}:5985/wsman", auth=(self._user, self._password), transport=self._transport)
        return self._sessions[target.name]

    def _exec(self, script: str, target: Target) -> ExecResult:
        start = now_ms()
        try:
            r = self._session(target).run_ps(script)
        except Exception as exc:  # noqa: BLE001 - transport errors are reported as a result, not a crash
            return ExecResult(start, now_ms(), 255, command=script, error=f"{type(exc).__name__}: {exc}")
        out = r.std_out.decode("utf-8", "replace") if isinstance(r.std_out, bytes) else str(r.std_out)
        err = r.std_err.decode("utf-8", "replace") if isinstance(r.std_err, bytes) else str(r.std_err)
        return ExecResult(start, now_ms(), int(r.status_code), out, err, script,
                          prevented=is_prevented(int(r.status_code), out, err))

    def run(self, test: AtomicTest, target: Target) -> ExecResult:
        if test.get_prereqs:
            self._exec(build_invoke(test, prereqs=True, atomics_path=target.atomics_path), target)
        return self._exec(build_invoke(test, atomics_path=target.atomics_path), target)

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None:
        return self._exec(build_invoke(test, cleanup=True, atomics_path=target.atomics_path), target)

    def close(self) -> None:
        self._sessions.clear()
