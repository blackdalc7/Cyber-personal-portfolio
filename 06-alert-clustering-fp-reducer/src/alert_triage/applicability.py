"""Signature applicability: what a target must have for an attack to be able to work at all.

Loaded from ``config/signature_requirements.yml``::

    - id: rdp
      match: "(?i)\\b(rdp|ms-wbt|bluekeep|terminal services)\\b"
      requires: {os_family: [windows], ports: [3389]}
      reason: RDP attacks need a Windows host listening on 3389/tcp

Each requirement is checked against the CMDB record of the target. Unknown assets are
never declared immune: missing context means "investigate", not "ignore".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .cmdb import Asset

OS_FAMILIES = {"windows", "linux", "macos", "network", "other"}


class RequirementError(ValueError):
    """Raised when the requirements YAML is malformed."""


@dataclass(frozen=True)
class Requirement:
    """What a family of attacks needs from its target (OS, open port or product) to succeed."""
    id: str
    pattern: re.Pattern[str]
    reason: str
    os_family: frozenset[str] = frozenset()
    ports: frozenset[int] = frozenset()
    products: tuple[str, ...] = ()

    def immunity(self, asset: Asset) -> list[str]:
        """Reasons the asset cannot be affected; empty if the attack is structurally possible."""
        reasons = []
        if self.os_family and asset.os_family not in self.os_family:
            reasons.append(f"targets {'/'.join(sorted(self.os_family))} but {asset.hostname} runs {asset.os_family}")
        # Port and product facts are only trusted when the CMDB has a service inventory for the
        # asset; an empty inventory means "not scanned", not "nothing listening".
        if self.ports and asset.services:
            open_ports = {s.port for s in asset.services}
            if not open_ports & self.ports:
                wanted = ",".join(str(p) for p in sorted(self.ports))
                reasons.append(f"needs port {wanted} but {asset.hostname} does not listen on it")
        if self.products and asset.services:
            have = " ".join(s.product.lower() + " " + s.service.lower() for s in asset.services)
            if not any(p in have for p in self.products):
                reasons.append(f"needs {' or '.join(self.products)} but {asset.hostname} does not run it")
        return reasons


@dataclass
class Applicability:
    """All loaded requirements, matched against alerts by rule name and signature."""
    requirements: list[Requirement] = field(default_factory=list)

    def for_alert(self, rule: str, signature: str) -> list[Requirement]:
        """Return the requirements whose pattern matches the alert's rule or signature."""
        text = f"{rule} {signature}"
        return [r for r in self.requirements if r.pattern.search(text)]


def load_requirements(path: str | Path) -> Applicability:
    """Load the structural requirements YAML.

    Raises:
        RequirementError: naming the entry with a bad regex or field.
    """
    data: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise RequirementError(f"{path}: expected a list of requirements")
    out = []
    for i, r in enumerate(data):
        where = f"{path}[{i}]"
        try:
            pattern = re.compile(str(r["match"]))
        except (KeyError, re.error) as exc:
            raise RequirementError(f"{where}: a valid 'match' regex is required ({exc})") from exc
        req = r.get("requires") or {}
        os_family = frozenset(str(x).lower() for x in req.get("os_family") or ())
        if os_family - OS_FAMILIES:
            raise RequirementError(f"{where}: unknown os_family {sorted(os_family - OS_FAMILIES)}")
        ports = frozenset(int(p) for p in req.get("ports") or ())
        products = tuple(str(p).lower() for p in req.get("products") or ())
        if not (os_family or ports or products):
            raise RequirementError(f"{where}: requires must name os_family, ports or products")
        out.append(Requirement(str(r.get("id", f"req{i}")), pattern, str(r.get("reason", "")), os_family, ports,
                               products))
    return Applicability(out)
