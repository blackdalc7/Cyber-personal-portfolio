"""Shared result type and protocol for the executors, plus detection of outputs that mean "prevented"."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Protocol

from ..campaign import AtomicTest, Target

# Output that means the endpoint's protection stopped the technique (scored "prevented", not "missed").
_PREVENTED = re.compile(
    r"(operation did not complete successfully because the file contains a virus"
    r"|this script contains malicious content and has been blocked"
    r"|blocked by your antivirus|has been quarantined|threat.*(removed|quarantined|blocked)"
    r"|access is denied.*defender|smartscreen prevented)",
    re.IGNORECASE,
)


def now_ms() -> int:
    return int(time.time() * 1000)


def is_prevented(rc: int, stdout: str, stderr: str) -> bool:
    return bool(_PREVENTED.search(f"{stdout}\n{stderr}")) and (rc != 0 or "blocked" in stderr.lower()
                                                                  or "quarantin" in f"{stdout}{stderr}".lower())


@dataclass
class ExecResult:
    """What happened when an executor ran (or failed to run) one atomic test."""
    started_ms: int
    ended_ms: int
    rc: int
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    prevented: bool = False
    executed: bool = True
    error: str | None = None

    def tail(self, n: int = 2000) -> dict[str, str]:
        """The last ``n`` characters of stdout and stderr, for the run document."""
        return {"stdout": self.stdout[-n:], "stderr": self.stderr[-n:]}


class Executor(Protocol):
    """Interface every executor implements: run a test, clean it up, release connections."""
    def run(self, test: AtomicTest, target: Target) -> ExecResult: ...

    def cleanup(self, test: AtomicTest, target: Target) -> ExecResult | None: ...

    def close(self) -> None: ...
