"""Build Invoke-AtomicTest command lines without ever letting campaign text become code."""

from __future__ import annotations

import base64

from ..campaign import AtomicTest


def ps_quote(value: str) -> str:
    """Single-quoted PowerShell literal (no interpolation; embedded quotes doubled)."""
    return "'" + value.replace("'", "''") + "'"


def _ps_value(value: str | int | bool) -> str:
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, int):
        return str(value)
    return ps_quote(value)


def build_invoke(test: AtomicTest, *, cleanup: bool = False, prereqs: bool = False,
                 atomics_path: str | None = None) -> str:
    """The PowerShell script for one Atomic test (or its cleanup / prerequisites)."""
    parts = ["Invoke-AtomicTest", ps_quote(test.technique)]
    if test.test_names:
        parts += ["-TestNames", ",".join(ps_quote(n) for n in test.test_names)]
    elif test.test_numbers:
        parts += ["-TestNumbers", ",".join(str(n) for n in test.test_numbers)]
    else:
        parts += ["-TestGuids", ",".join(ps_quote(g) for g in test.test_guids)]
    if test.input_args:
        pairs = "; ".join(f"{ps_quote(k)} = {_ps_value(v)}" for k, v in sorted(test.input_args.items()))
        parts += ["-InputArgs", f"@{{ {pairs} }}"]
    if atomics_path:
        parts += ["-PathToAtomicsFolder", ps_quote(atomics_path)]
    parts += ["-TimeoutSeconds", str(test.timeout_s)]
    if cleanup:
        parts.append("-Cleanup")
    elif prereqs:
        parts.append("-GetPrereqs")
    return ("$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'; "
            "Import-Module invoke-atomicredteam -ErrorAction Stop; " + " ".join(parts) + " -Confirm:$false")


def encode_ps(script: str) -> str:
    """Base64 UTF-16LE for ``pwsh -EncodedCommand``: no shell quoting anywhere on the way."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")
