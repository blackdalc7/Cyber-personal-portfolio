"""Seeded generator of simulated, benign SIEM alerts with ground-truth labels.

The output is alert *metadata* only: rule names, addresses, ports and severities, as a SIEM
would forward them. No packets, payloads or exploit content are produced. Addresses come
from RFC 1918 (internal) and RFC 5737 documentation ranges (external) and match
``examples/cmdb_seed.yml``.

Each scenario carries a ``label`` used only by ``evaluate`` to measure the engine:

* ``false_positive``: the detection cannot be real on that asset (wrong OS, port or product)
* ``benign``: the activity is real but expected (authorised scanner, maintenance, background noise)
* ``true_positive``: an analyst needs to act
"""

from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DAY = datetime(2026, 10, 26, tzinfo=timezone.utc)
WEB = ["10.20.1.10", "10.20.1.11", "10.20.1.12"]
SERVERS = [*WEB, "10.20.2.20", "10.20.3.30", "10.20.4.40", "10.20.4.41", "10.20.4.42", "10.20.5.50"]
EXT_A, EXT_B, EXT_C = "203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"
COMMON_PORTS = [21, 23, 25, 80, 110, 143, 443, 3306, 5900, 6379, 8080, 8443]


@dataclass(frozen=True)
class Scenario:
    """One simulated alert source: a rule, who fires it at whom, when, and its ground-truth label."""
    name: str
    label: str
    rule: str
    category: str
    severity: str
    sources: tuple[str, ...]        # IPs or CIDRs
    targets: tuple[str, ...]
    ports: tuple[int, ...]
    start_h: float
    end_h: float
    base_count: int
    signature: str = ""
    sensor: str = "ids-dmz-01"
    protocol: str = "tcp"
    variants: tuple[str, ...] = ()  # optional signature detail, so near-duplicates are not identical


SCENARIOS: tuple[Scenario, ...] = (
    # --- benign: authorised activity and expected noise ---------------------------------
    Scenario("authorised-port-scan", "benign", "ET SCAN Nmap SYN scan", "reconnaissance", "low",
             ("10.0.5.10", "10.0.5.11"), tuple(SERVERS), tuple(range(1, 1025, 7)), 0.5, 2.5, 1800,
             "TCP SYN sweep across multiple ports", "ids-core-01"),
    Scenario("authorised-vuln-scan", "benign", "ET SCAN Nessus User-Agent observed", "reconnaissance", "low",
             ("10.0.5.10",), (*WEB, "10.20.2.20"), (80, 443, 8443), 0.6, 2.4, 400,
             "HTTP requests with a vulnerability scanner user agent", "ids-core-01"),
    Scenario("internet-background-scan", "benign", "Inbound probe to common service ports", "reconnaissance",
             "low", (EXT_A, EXT_B, EXT_C), (*WEB, "10.20.5.50"), tuple(COMMON_PORTS), 0.0, 23.99, 600,
             "Unsolicited inbound connection attempts from the internet",
             variants=("tcp syn", "tcp connect", "banner grab", "masscan fingerprint", "zgrab fingerprint")),
    Scenario("db-maintenance-stop", "benign", "PostgreSQL service stopped unexpectedly", "availability", "medium",
             ("10.40.0.5",), ("10.20.3.30",), (5432,), 1.2, 1.4, 60, "postgres service state changed to stopped",
             "siem-host-01"),
    Scenario("db-maintenance-config", "benign", "Configuration file modified on database server", "change",
             "medium", ("10.40.0.5",), ("10.20.3.30",), (22,), 1.1, 3.2, 60,
             "postgresql.conf modified by an administrative session", "siem-host-01"),
    Scenario("nrd-dns", "benign", "DNS query for newly registered domain", "dns", "low",
             ("10.30.10.0/27",), ("10.20.4.40",), (53,), 7.0, 18.0, 200,
             "Resolution of a domain registered in the last 30 days", "dns-sensor-01", "udp"),
    # --- structural false positives: the attack cannot work on that asset ----------------
    Scenario("bluekeep-vs-linux", "false_positive", "ET EXPLOIT Possible BlueKeep RDP exploitation attempt",
             "exploit", "high", (EXT_B,), tuple(WEB), (3389,), 0.0, 23.99, 700,
             "RDP connection request matching BlueKeep exploitation pattern",
             variants=("ms_t120 channel bind", "mstshash cookie", "virtual channel request")),
    Scenario("rdp-brute-vs-linux", "false_positive", "GPL RDP brute force login attempts", "credential-access",
             "medium", (EXT_A,), tuple(WEB), (3389,), 0.0, 23.99, 300, "Repeated RDP connection attempts",
             variants=("nla failure", "tls handshake", "x224 request")),
    Scenario("eternalblue-vs-linux", "false_positive", "ET EXPLOIT EternalBlue SMB exploitation attempt",
             "exploit", "high", (EXT_A,), (*WEB, "10.20.2.20"), (445,), 0.0, 23.99, 400,
             "SMBv1 transaction matching MS17-010 exploitation pattern",
             variants=("trans2 request", "nt trans", "doublepulsar ping")),
    Scenario("iis-vs-nginx", "false_positive", "ET WEB_SERVER IIS WebDAV exploitation attempt", "exploit",
             "medium", (EXT_B,), ("10.20.1.10", "10.20.1.11"), (443,), 0.0, 23.99, 300,
             "PROPFIND request matching IIS WebDAV exploitation pattern",
             variants=("long if header", "translate header")),
    Scenario("struts-vs-iis", "false_positive", "ET WEB_SPECIFIC_APPS Apache Struts2 OGNL injection attempt",
             "exploit", "high", ("10.40.0.0/28",), ("10.20.4.42",), (443,), 9.0, 11.0, 200,
             "HTTP request matching Struts2 OGNL expression pattern", "ids-core-01"),
    Scenario("citrix-vs-nginx", "false_positive", "ET EXPLOIT Citrix ADC path traversal attempt", "exploit",
             "high", (EXT_B,), tuple(WEB), (443,), 0.0, 23.99, 150,
             "HTTP request matching CVE-2019-19781 path pattern", variants=("vpns path", "newbm pl", "smb conf")),
    # --- true positives -------------------------------------------------------------------
    Scenario("ssh-brute-bastion", "true_positive", "SSH brute force: repeated authentication failures",
             "credential-access", "high", ("198.51.100.77",), ("10.20.5.50",), (22,), 13.0, 13.4, 250,
             "More than 20 failed SSH logins from one source in 60 seconds", "siem-host-01"),
    Scenario("ssh-success-after-brute", "true_positive", "Successful SSH login after repeated failures",
             "initial-access", "critical", ("198.51.100.77",), ("10.20.5.50",), (22,), 13.41, 13.42, 1,
             "Accepted password for user deploy after 214 failures", "siem-host-01"),
    Scenario("kerberoast", "true_positive", "Kerberoasting: excessive RC4 service ticket requests",
             "credential-access", "high", ("10.30.10.15",), ("10.20.4.40",), (88,), 14.0, 14.2, 30,
             "TGS requests with RC4 encryption for many service accounts", "dc-sensor-01"),
    Scenario("lsass-access", "true_positive", "Credential dumping: LSASS memory access by unsigned process",
             "credential-access", "critical", ("10.30.10.15",), ("10.30.10.15",), (), 14.3, 14.35, 3,
             "Unsigned process opened lsass.exe with PROCESS_VM_READ", "edr"),
    Scenario("c2-beacon", "true_positive", "Outbound connection to threat-intel C2 indicator", "command-and-control",
             "high", ("10.30.10.15",), ("203.0.113.200",), (443,), 14.4, 16.0, 40,
             "Periodic HTTPS connections to an indicator on the internal block list", "proxy-01"),
    Scenario("sqli-app01", "true_positive", "ET WEB_SERVER SQL injection attempt in query string", "exploit",
             "medium", ("203.0.113.45", "203.0.113.46"), ("10.20.2.20",), (8443,), 10.0, 10.5, 80,
             "Query string containing SQL boolean tautology pattern",
             variants=("union select", "boolean tautology", "time delay function", "comment sequence")),
    Scenario("telnet-unknown-host", "true_positive", "Telnet login attempt to unregistered host", "policy",
             "medium", ("10.40.0.0/28",), ("10.20.9.99",), (23,), 11.0, 11.5, 50,
             "Cleartext Telnet session to a host with no CMDB record", "ids-core-01"),
)


def _pick_ip(rng: random.Random, pool: tuple[str, ...]) -> str:
    choice = rng.choice(pool)
    if "/" not in choice:
        return choice
    net = ipaddress.ip_network(choice)
    return str(net.network_address + rng.randrange(1, net.num_addresses - 1))


def generate(count: int = 5000, seed: int = 7) -> list[dict[str, Any]]:
    """Return ``count`` simulated alerts (approximately: each scenario keeps at least one)."""
    if count < len(SCENARIOS):
        raise ValueError(f"count must be at least {len(SCENARIOS)}")
    rng = random.Random(seed)
    total = sum(s.base_count for s in SCENARIOS)
    alerts = []
    for s in SCENARIOS:
        n = max(1, round(s.base_count * count / total))
        for _ in range(n):
            offset = rng.uniform(s.start_h, s.end_h) * 3600
            ts = DAY + timedelta(seconds=round(offset, 3))
            alerts.append({
                "timestamp": ts.isoformat().replace("+00:00", "Z"), "rule": s.rule, "category": s.category,
                "severity": s.severity, "src_ip": _pick_ip(rng, s.sources), "dst_ip": _pick_ip(rng, s.targets),
                "dst_port": rng.choice(s.ports) if s.ports else None, "protocol": s.protocol,
                "signature": " ".join(filter(None, [s.signature or s.rule,
                                                    rng.choice(s.variants) if s.variants else ""])),
                "sensor": s.sensor, "scenario": s.name, "label": s.label,
            })
    alerts.sort(key=lambda a: a["timestamp"])
    for i, a in enumerate(alerts, start=1):
        a["id"] = f"SIM-{i:06d}"
    return alerts


def write(path: str | Path, count: int = 5000, seed: int = 7) -> int:
    """Generate ``count`` labelled alerts and write them as JSON, one alert per line.

    Returns the number of alerts written.
    """
    alerts = generate(count, seed)
    doc = {"simulated": True, "seed": seed, "generated_for": DAY.date().isoformat(), "alerts": alerts}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # One alert per line keeps the file diff-able and greppable without bloating it.
    head = json.dumps({k: v for k, v in doc.items() if k != "alerts"})[:-1]
    body = ",\n".join(json.dumps(a, separators=(",", ":")) for a in alerts)
    Path(path).write_text(f'{head}, "alerts": [\n{body}\n]}}\n', encoding="utf-8")
    return len(alerts)
