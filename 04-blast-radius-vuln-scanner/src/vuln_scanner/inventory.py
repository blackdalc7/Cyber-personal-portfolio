"""Asset inventory and network policy (YAML).

The scanner only knows what is listening. Blast radius also needs to know *who can reach
whom* and *what matters*. That comes from a small, reviewable YAML file the network and
asset owners already have in some form (firewall policy, CMDB):

    intra_zone: allow                      # hosts in the same zone can reach each other
    assets:
      - {ip: 10.0.1.10, name: web01, zone: dmz, criticality: 3}
    flows:
      - {from: internet, to: dmz, ports: [80, 443]}
      - {from: dmz, to: app, ports: [8080]}
      - {from: 10.0.2.20, to: 10.0.3.5, ports: [5432]}
      - {from: corp, to: any, ports: any}
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("vuln_scanner.inventory")
INTERNET = "internet"
ANY = "any"


class InventoryError(ValueError):
    """Raised when the inventory YAML is malformed."""


@dataclass(frozen=True)
class Asset:
    """One known host: name, network zone, business criticality (1-5), owner and tags."""
    ip: str
    name: str
    zone: str
    criticality: int = 2
    owner: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Flow:
    """A firewall rule allowing traffic from zone or host ``src`` to ``dst``."""
    src: str
    dst: str
    ports: frozenset[int] | None   # None = any port

    def permits(self, port: int) -> bool:
        """True if this flow allows ``port`` (a flow without ports allows every port)."""
        return self.ports is None or port in self.ports


@dataclass
class Inventory:
    """Asset inventory plus network policy, used to decide what can reach what.

    An empty inventory means every host is reachable from every other host,
    which is the safe worst case.
    """
    assets: dict[str, Asset] = field(default_factory=dict)
    flows: list[Flow] = field(default_factory=list)
    intra_zone: bool = True
    default_criticality: int = 2

    def asset(self, ip: str) -> Asset:
        """Return the asset for ``ip``, or a default unknown asset if it is not listed."""
        found = self.assets.get(ip)
        if found is None:
            return Asset(ip=ip, name=ip, zone="unknown", criticality=self.default_criticality)
        return found

    @staticmethod
    def _selector_matches(selector: str, ip: str, zone: str) -> bool:
        return selector in (ANY, ip, zone)

    def allowed_ports(self, src_ip: str, src_zone: str, dst: Asset, open_ports: set[int]) -> set[int]:
        """Open ports on ``dst`` that policy lets ``src`` reach."""
        if src_ip == dst.ip:
            return set()
        if self.intra_zone and src_zone == dst.zone and src_zone not in (INTERNET, "unknown"):
            return set(open_ports)
        allowed: set[int] = set()
        for f in self.flows:
            if self._selector_matches(f.src, src_ip, src_zone) and self._selector_matches(f.dst, dst.ip, dst.zone):
                allowed |= {p for p in open_ports if f.permits(p)}
        return allowed


def _ports(value: Any, where: str) -> frozenset[int] | None:
    if value in (None, ANY, "*"):
        return None
    if isinstance(value, int):
        value = [value]
    if not isinstance(value, list):
        raise InventoryError(f"{where}: ports must be a list, a single port or 'any'")
    out = set()
    for p in value:
        if isinstance(p, str) and "-" in p:
            lo, hi = (int(x) for x in p.split("-", 1))
            out |= set(range(lo, hi + 1))
        else:
            out.add(int(p))
    if any(not 0 < p < 65536 for p in out):
        raise InventoryError(f"{where}: ports must be 1-65535")
    return frozenset(out)


def load_inventory(path: str | Path | None) -> Inventory:
    """Load and validate an inventory YAML file. ``None`` returns an empty inventory.

    Raises:
        InventoryError: naming the entry that failed validation.
    """
    if path is None:
        return Inventory()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise InventoryError("inventory must be a mapping")
    inv = Inventory(intra_zone=str(data.get("intra_zone", "allow")).lower() == "allow",
                    default_criticality=int(data.get("default_criticality", 2)))
    for i, a in enumerate(data.get("assets") or []):
        where = f"assets[{i}]"
        try:
            ip = str(ipaddress.ip_address(str(a["ip"])))
        except (KeyError, ValueError) as exc:
            raise InventoryError(f"{where}: a valid 'ip' is required") from exc
        crit = int(a.get("criticality", inv.default_criticality))
        if not 1 <= crit <= 5:
            raise InventoryError(f"{where}: criticality must be 1-5")
        zone = str(a.get("zone", "unknown"))
        if zone in (INTERNET, ANY):
            raise InventoryError(f"{where}: zone '{zone}' is reserved")
        inv.assets[ip] = Asset(ip=ip, name=str(a.get("name", ip)), zone=zone, criticality=crit,
                               owner=str(a.get("owner", "")), tags=tuple(a.get("tags") or ()))
    for i, f in enumerate(data.get("flows") or []):
        where = f"flows[{i}]"
        if "from" not in f or "to" not in f:
            raise InventoryError(f"{where}: 'from' and 'to' are required")
        if str(f["to"]) == INTERNET:
            continue   # egress does not widen the internal blast radius
        inv.flows.append(Flow(str(f["from"]), str(f["to"]), _ports(f.get("ports", ANY), where)))
    return inv
