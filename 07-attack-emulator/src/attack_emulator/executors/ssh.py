from __future__ import annotations

from pathlib import Path
from typing import Any

from ..campaign import AtomicTest, Target
from .base import ExecResult, is_prevented, now_ms
from .powershell import build_invoke, encode_ps


class SshExecutor:
    """Runs atomics on a Linux lab VM over SSH with ``pwsh -EncodedCommand`` (no shell interpolation of args).

    Host keys are verified against known_hosts unless ``trust_lab_hostkeys`` is set, which is only reasonable for
    throwaway Vagrant VMs whose keys change on every rebuild.
    """

    def __init__(self, user: str, key: Path | None, trust_lab_hostkeys: bool = False,
                 client_factory: Any = None) -> None:
        self._user, self._key, self._trust = user, key, trust_lab_hostkeys
        self._factory = client_factory
        self._clients: dict[str, Any] = {}

    def _client(self, target: Target) -> Any:
        if target.name not in self._clients:
            if self._factory is None:
                import paramiko

                def make() -> Any:
                    c = paramiko.SSHClient()
                    c.load_system_host_keys()
                    c.set_missing_host_key_policy(
                        paramiko.AutoAddPolicy() if self._trust else paramiko.RejectPolicy())
                    return c

                self._factory = make
            client = self._factory()
            client.connect(target.address, username=self._user,
                           key_filename=str(self._key) if self._key else None, timeout=15)
            self._clients[target.name] = client
        return self._clients[target.name]

    def _exec(self, script: str, target: Target, timeout: int) -> ExecResult:
        start = now_ms()
        try:
            cmd = f"sudo -n pwsh -NoProfile -NonInteractive -EncodedCommand {encode_ps(script)}"
            _, stdout, stderr = self._client(target).exec_command(cmd, timeout=timeout + 30)
            rc = stdout.channel.recv_exit_status()
            out, err = stdout.read().decode("utf-8", "replace"), stderr.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 - transport errors are reported as a result
            return ExecResult(start, now_ms(), 255, command=script, error=f"{type(exc).__name__}: {exc}")
        return ExecResult(start, now_ms(), rc, out, err, script, prevented=is_prevented(rc, out, err))

    def run(self, test: AtomicTest, target: Target) -> ExecResult:
        if test.get_prereqs:
            self._exec(build_invoke(test, prereqs=True, atomics_path=target.atomics_path), target, test.timeout_s)
        return self._exec(build_invoke(test, atomics_path=target.atomics_path), target, test.timeout_s)

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None:
        return self._exec(build_invoke(test, cleanup=True, atomics_path=target.atomics_path), target, test.timeout_s)

    def close(self) -> None:
        for c in self._clients.values():
            c.close()
        self._clients.clear()
