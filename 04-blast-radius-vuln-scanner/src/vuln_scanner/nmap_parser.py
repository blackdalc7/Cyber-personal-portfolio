"""Nmap XML → services. Parsed with defusedxml: scan files are untrusted input (XXE / billion laughs)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree as SafeET

_PORT_LINE = re.compile(r'<port\s+protocol="(?P<proto>\w+)"\s+portid="(?P<port>\d+)"')
_HOST_OPEN = re.compile(r"<host[\s>]")
_ADDR_LINE = re.compile(r'<address\s+addr="(?P<addr>[^"]+)"\s+addrtype="ipv[46]"')


@dataclass(frozen=True)
class Service:
    """One open port found by Nmap, with its service detection results.

    ``source_file`` and ``line`` point back into the scan XML, for SARIF locations.
    """
    host: str
    port: int
    protocol: str
    name: str
    product: str = ""
    version: str = ""
    cpe: str = ""
    hostname: str = ""
    source_file: str = ""
    line: int = 1

    @property
    def key(self) -> str:
        """Identity of the service as ``host:port/protocol``."""
        return f"{self.host}:{self.port}/{self.protocol}"

    @property
    def banner(self) -> str:
        """Human-readable product and version, falling back to the service name."""
        return " ".join(x for x in (self.product, self.version) if x) or self.name or "unknown"


def cpe22_to_23(cpe: str) -> str:
    """``cpe:/a:apache:http_server:2.4.49`` → ``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        raise ValueError(f"not a CPE: {cpe!r}")
    parts = cpe[len("cpe:/"):].split(":")
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(p or "*" for p in parts[:11])


def _line_index(text: str) -> dict[tuple[str, int, str], int]:
    """Map (host, port, proto) to its line in the XML so SARIF results point at real evidence."""
    index: dict[tuple[str, int, str], int] = {}
    host = ""
    for n, line in enumerate(text.splitlines(), start=1):
        if _HOST_OPEN.search(line):
            host = ""
        m = _ADDR_LINE.search(line)
        if m and not host:
            host = m.group("addr")
        for p in _PORT_LINE.finditer(line):
            index.setdefault((host, int(p.group("port")), p.group("proto")), n)
    return index


def parse_nmap_xml(path: str | Path, include_filtered: bool = False) -> list[Service]:
    """Parse an Nmap ``-oX`` file into a list of open services.

    The XML is parsed with defusedxml. Hosts that are down are skipped, and
    filtered ports only count when ``include_filtered`` is set.

    Raises:
        ValueError: if the file is not Nmap XML.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    root = SafeET.fromstring(text)
    if root.tag != "nmaprun":
        raise ValueError(f"{path} is not Nmap XML (root <{root.tag}>)")
    lines = _line_index(text)
    services: list[Service] = []
    for host in root.iter("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name", "") if hn is not None else ""
        for port in host.iter("port"):
            state = port.find("state")
            st = state.get("state") if state is not None else ""
            if st != "open" and not (include_filtered and st == "open|filtered"):
                continue
            svc = port.find("service")
            cpe_el = svc.find("cpe") if svc is not None else None
            proto = port.get("protocol", "tcp")
            portid = int(port.get("portid", "0"))
            services.append(Service(
                host=addr, port=portid, protocol=proto,
                name=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                cpe=(cpe_el.text or "").strip() if cpe_el is not None else "",
                hostname=hostname, source_file=path.as_posix(),
                line=lines.get((addr, portid, proto), 1),
            ))
    return services
