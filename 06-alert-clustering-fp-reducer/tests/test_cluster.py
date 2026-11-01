"""Tests for alert documents and clustering into meta-alerts."""

from conftest import make_alert

from alert_triage.cluster import alert_document, cluster_alerts


def test_documents_describe_behaviour():
    doc = alert_document(
        make_alert(
            "ET EXPLOIT EternalBlue",
            src="198.51.100.7",
            dst="10.20.1.10",
            port=445,
            signature="SMB MS17-010 the attempt",
        )
    )
    tokens = doc.split()
    assert tokens.count("rule_et_exploit_eternalblue") == 3
    assert {"srcnet_198_51_100_0", "dstnet_10_20_1_0", "dport_445", "sig_smb", "sig_ms17"} <= set(tokens)
    assert "sig_the" not in tokens and "sig_010" not in tokens


def test_scans_are_sweeps():
    a = alert_document(make_alert(category="reconnaissance", dst="10.20.1.10", port=22))
    b = alert_document(make_alert(category="reconnaissance", dst="10.20.4.40", port=8080))
    assert a == b and "dport_sweep" in a and "dstnet_10_20_0_0" in a


def test_empty_and_single():
    assert cluster_alerts([]).meta_alerts == []
    res = cluster_alerts([make_alert()])
    assert len(res.meta_alerts) == 1 and res.meta_alerts[0].id == "MA-0001" and res.unique_documents == 1


def test_duplicates_merge_and_rules_stay_apart():
    alerts = [
        make_alert("GPL RDP brute force", offset_s=i, src=f"198.51.100.{i % 50 + 1}", port=3389) for i in range(300)
    ]
    alerts += [
        make_alert(
            "ET WEB_SERVER SQL injection",
            offset_s=i,
            src="203.0.113.9",
            dst="10.20.2.20",
            port=8443,
            severity="high",
            label="true_positive",
        )
        for i in range(20)
    ]
    res = cluster_alerts(sorted(alerts, key=lambda a: a.timestamp))
    assert sorted(m.count for m in res.meta_alerts) == [20, 300]
    sqli = next(m for m in res.meta_alerts if m.count == 20)
    assert sqli.rules == ["ET WEB_SERVER SQL injection"] and sqli.severity == "high"
    assert sqli.labels == {"true_positive": 20} and sqli.targets == ["10.20.2.20"] and sqli.ports == [8443]
    assert 0.99 <= sqli.cohesion <= 1.0 and res.unique_documents == 2


def test_near_duplicates_merge_on_signature_variation():
    # IDF is corpus-relative: shared tokens only count as distinctive next to other detections,
    # as in any real alert stream.
    alerts = [
        make_alert("ET EXPLOIT BlueKeep", offset_s=i, port=3389, signature=f"rdp bluekeep {v}")
        for i, v in enumerate(["ms_t120 bind", "mstshash cookie", "virtual channel"] * 10)
    ]
    others = [
        make_alert(
            f"Other rule {n}",
            src=f"203.0.{n}.1",
            dst=f"10.{n}.0.1",
            port=n + 1,
            category=f"c{n}",
            signature=f"unrelated {n} text",
        )
        for n in range(40)
    ]
    res = cluster_alerts(alerts + others)
    blue = [m for m in res.meta_alerts if m.rules == ["ET EXPLOIT BlueKeep"]]
    assert len(blue) == 1 and blue[0].count == 30 and blue[0].cohesion < 1 and len(res.meta_alerts) == 41


def test_time_gap_splits_sessions_and_summary():
    alerts = [make_alert(offset_s=s) for s in (0, 60, 120, 10_000, 10_060)]
    res = cluster_alerts(alerts, time_window_s=3600)
    assert [m.count for m in res.meta_alerts] == [3, 2]
    first = res.meta_alerts[0].summary()
    assert first["id"] == "MA-0001" and first["count"] == 3 and first["source_subnets"] == ["198.51.100.0/24"]
    assert first["first_seen"] < first["last_seen"]


def test_kmeans_with_silhouette():
    alerts = []
    for n, rule in enumerate(["Rule A alpha", "Rule B beta", "Rule C gamma", "Rule D delta"]):
        alerts += [
            make_alert(rule, offset_s=i, dst=f"10.{n}.0.1", port=1000 + n, signature=f"{rule} v{i % 2}")
            for i in range(10)
        ]
    res = cluster_alerts(alerts, algorithm="kmeans", kmeans_max_k=6)
    assert res.algorithm == "kmeans" and res.silhouette is not None
    assert sorted(m.count for m in res.meta_alerts) == [10, 10, 10, 10]


def test_kmeans_tiny_input():
    res = cluster_alerts([make_alert("A"), make_alert("B")], algorithm="kmeans")
    assert len(res.meta_alerts) == 1 and res.silhouette is None
