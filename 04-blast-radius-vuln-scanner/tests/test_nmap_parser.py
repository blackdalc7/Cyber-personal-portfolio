"""Tests for Nmap XML parsing, CPE conversion and XXE protection."""

import pytest
from conftest import EXAMPLES
from defusedxml import EntitiesForbidden

from vuln_scanner.nmap_parser import cpe22_to_23, parse_nmap_xml


def test_parses_open_services_and_skips_down_hosts_and_filtered_ports(lab_services):
    keys = {s.key for s in lab_services}
    assert len(lab_services) == 11
    assert "10.10.1.10:80/tcp" in keys
    assert not any(s.host == "10.10.9.99" for s in lab_services)  # host down
    assert "10.10.5.50:23/tcp" not in keys  # filtered


def test_service_fields_and_banner(lab_services):
    web = next(s for s in lab_services if s.key == "10.10.1.10:80/tcp")
    assert (web.product, web.version, web.cpe) == ("Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49")
    assert web.hostname == "web01.lab.example"
    assert web.banner == "Apache httpd 2.4.49"


def test_line_numbers_point_at_the_port_element(lab_services):
    lines = (EXAMPLES / "lab_scan.xml").read_text().splitlines()
    for s in lab_services:
        assert f'portid="{s.port}"' in lines[s.line - 1]


@pytest.mark.parametrize(
    ("cpe", "expected"),
    [
        ("cpe:/a:apache:http_server:2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
        ("cpe:/o:microsoft:windows", "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"),
        ("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"),
    ],
)
def test_cpe_conversion(cpe, expected):
    assert cpe22_to_23(cpe) == expected


def test_cpe_conversion_rejects_garbage():
    with pytest.raises(ValueError):
        cpe22_to_23("apache 2.4")


def test_rejects_xxe(tmp_path):
    evil = tmp_path / "evil.xml"
    evil.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>')
    with pytest.raises(EntitiesForbidden):
        parse_nmap_xml(evil)


def test_rejects_non_nmap_xml(tmp_path):
    other = tmp_path / "other.xml"
    other.write_text("<report/>")
    with pytest.raises(ValueError, match="not Nmap XML"):
        parse_nmap_xml(other)


def test_open_filtered_is_opt_in(tmp_path):
    f = tmp_path / "udp.xml"
    f.write_text(
        '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port>'
        "</ports></host></nmaprun>"
    )
    assert parse_nmap_xml(f) == []
    assert parse_nmap_xml(f, include_filtered=True)[0].key == "10.0.0.1:161/udp"
