"""Tests for inventory loading and network policy evaluation."""

import pytest

from vuln_scanner.inventory import Inventory, InventoryError, load_inventory


def write(tmp_path, text):
    p = tmp_path / "inv.yml"
    p.write_text(text)
    return p


def test_loads_assets_and_flows(lab_inventory):
    assert lab_inventory.asset("10.10.3.30").criticality == 5
    assert lab_inventory.asset("10.10.3.30").tags == ("pci", "pii")
    assert len(lab_inventory.flows) == 7


def test_unknown_hosts_get_defaults(lab_inventory):
    a = lab_inventory.asset("192.0.2.7")
    assert (a.zone, a.criticality, a.name) == ("unknown", 2, "192.0.2.7")


def test_policy_evaluation(lab_inventory):
    db = lab_inventory.asset("10.10.3.30")
    web = lab_inventory.asset("10.10.1.10")
    assert lab_inventory.allowed_ports("internet", "internet", web, {22, 80}) == {80}
    assert lab_inventory.allowed_ports("10.10.2.20", "app", db, {5432, 22}) == {5432}
    assert lab_inventory.allowed_ports("10.10.1.10", "dmz", db, {5432}) == set()
    assert lab_inventory.allowed_ports("10.10.5.50", "mgmt", db, {5432, 9999}) == {5432}
    assert lab_inventory.allowed_ports("10.10.2.21", "app", lab_inventory.asset("10.10.2.20"), {8009}) == {8009}
    assert lab_inventory.allowed_ports(db.ip, db.zone, db, {5432}) == set()  # no self edges


def test_intra_zone_deny(tmp_path):
    inv = load_inventory(
        write(tmp_path, "intra_zone: deny\nassets:\n - {ip: 10.0.0.1, zone: a}\n - {ip: 10.0.0.2, zone: a}\n")
    )
    assert inv.allowed_ports("10.0.0.1", "a", inv.asset("10.0.0.2"), {22}) == set()


def test_port_ranges_any_and_egress(tmp_path):
    inv = load_inventory(
        write(
            tmp_path,
            """
flows:
  - {from: a, to: b, ports: ["8000-8002", 22]}
  - {from: c, to: any, ports: any}
  - {from: b, to: internet, ports: [443]}
""",
        )
    )
    assert inv.flows[0].ports == frozenset({22, 8000, 8001, 8002})
    assert inv.flows[1].ports is None
    assert len(inv.flows) == 2


@pytest.mark.parametrize(
    ("text", "msg"),
    [
        ("assets:\n - {name: x}\n", "valid 'ip'"),
        ("assets:\n - {ip: 10.0.0.1, criticality: 9}\n", "criticality"),
        ("assets:\n - {ip: 10.0.0.1, zone: internet}\n", "reserved"),
        ("flows:\n - {from: a}\n", "'from' and 'to'"),
        ("flows:\n - {from: a, to: b, ports: [70000]}\n", "1-65535"),
        ("flows:\n - {from: a, to: b, ports: {x: 1}}\n", "must be a list"),
        ("- just\n- a list\n", "mapping"),
    ],
)
def test_validation(tmp_path, text, msg):
    with pytest.raises(InventoryError, match=msg):
        load_inventory(write(tmp_path, text))


def test_no_inventory_means_empty_policy():
    assert load_inventory(None).flows == []
    assert isinstance(load_inventory(None), Inventory)
