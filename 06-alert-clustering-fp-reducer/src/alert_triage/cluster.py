"""Collapse near-duplicate alerts into meta-alerts with TF-IDF + DBSCAN (or K-Means).

Each alert becomes a short "document" of typed tokens describing *behaviour*, not identity:

    rule_et_scan_nmap_syn cat_recon sig_nmap sig_syn srcnet_203_0_113 dstnet_10_20_1 dport_22 proto_tcp

* Source and destination are reduced to their /24 (``srcnet_``/``dstnet_``), so 500 probes
  from one scanner subnet against one server segment produce near-identical documents.
  For reconnaissance categories the port is dropped and the target widened to its /16,
  because a scan is by definition a sweep: 500 "Port Scan Detected" alerts become one.
* Rule tokens are repeated (``rule_weight``) so two different detections never merge just
  because they share a subnet.
* TF-IDF down-weights tokens that appear everywhere (``proto_tcp``) and up-weights the
  distinctive ones; with L2-normalised vectors cosine distance is a fair similarity.

DBSCAN (metric=cosine, min_samples=1) then links every document to all neighbours within
``eps``: it needs no k, finds clusters of any shape, and is deterministic. Identical
documents are collapsed first and passed as ``sample_weight``, so 5,000 alerts usually
cluster as a few hundred unique vectors. K-Means is available for comparison, with k
chosen by silhouette score.

Finally each cluster is split into sessions wherever the gap between consecutive alerts
exceeds ``time_window_s``: the same scan next Tuesday is a new incident, not a duplicate.
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.cluster import DBSCAN, KMeans
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score

from .alerts import SEVERITIES, Alert

_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "of", "to", "on", "in", "for", "and", "or", "from", "via", "with", "detected", "attempt",
         "possible", "potential", "et", "gpl"}
_SWEEP_CATEGORIES = ("recon", "scan", "discovery")


def _net(ip: str, prefix_v4: int = 24, prefix_v6: int = 64) -> str:
    if not ip:
        return "none"
    addr = ipaddress.ip_address(ip)
    net = ipaddress.ip_network(f"{ip}/{prefix_v4 if addr.version == 4 else prefix_v6}", strict=False)
    return str(net.network_address).replace(".", "_").replace(":", "_")


def _slug(text: str) -> str:
    return "_".join(_WORD.findall(text.lower()))[:80] or "none"


def is_sweep(alert: Alert) -> bool:
    """True for scan and sweep categories, where exact ports and hosts are noise."""
    category = alert.category.lower()
    return any(k in category for k in _SWEEP_CATEGORIES)


def alert_document(alert: Alert, rule_weight: int = 3) -> str:
    """Turn an alert into a token document for TF-IDF.

    The rule name is repeated ``rule_weight`` times so alerts from the same rule
    cluster together. Network fields are bucketed (/24, or /16 for sweeps) so
    near-identical alerts produce identical documents.
    """
    sig_words = [w for w in _WORD.findall(alert.signature.lower()) if w not in _STOP and not w.isdigit()][:12]
    tokens = [f"rule_{_slug(alert.rule)}"] * rule_weight
    if is_sweep(alert):
        # A scan *is* a sweep over ports and hosts: the exact port and /24 are noise, the
        # scanner and the segment it sweeps are the behaviour.
        dst, port = f"dstnet_{_net(alert.dst_ip, 16, 48)}", "dport_sweep"
    else:
        dst, port = f"dstnet_{_net(alert.dst_ip)}", f"dport_{alert.dst_port if alert.dst_port is not None else 'none'}"
    tokens += [f"cat_{_slug(alert.category)}", f"srcnet_{_net(alert.src_ip)}", dst, port,
               f"proto_{alert.protocol or 'none'}"]
    tokens += [f"sig_{w}" for w in sig_words]
    return " ".join(tokens)


@dataclass
class MetaAlert:
    """A cluster of related alerts, presented to an analyst as one item."""
    id: str
    alerts: list[Alert]
    cohesion: float                       # mean cosine similarity of members to the centroid
    representative: Alert
    labels: Counter = field(default_factory=Counter)

    @property
    def count(self) -> int:
        """Number of raw alerts in the cluster."""
        return len(self.alerts)

    @property
    def first_seen(self) -> datetime:
        """Timestamp of the earliest alert."""
        return self.alerts[0].timestamp

    @property
    def last_seen(self) -> datetime:
        """Timestamp of the latest alert."""
        return self.alerts[-1].timestamp

    @property
    def rules(self) -> list[str]:
        """Rule names in the cluster, most frequent first."""
        return [r for r, _ in Counter(a.rule for a in self.alerts).most_common()]

    @property
    def severity(self) -> str:
        """Highest severity among the member alerts."""
        return SEVERITIES[max(a.severity_rank for a in self.alerts)]

    @property
    def sources(self) -> list[str]:
        """Source IPs, most frequent first."""
        return [ip for ip, _ in Counter(a.src_ip for a in self.alerts if a.src_ip).most_common()]

    @property
    def targets(self) -> list[str]:
        """Destination IPs, most frequent first."""
        return [ip for ip, _ in Counter(a.dst_ip for a in self.alerts if a.dst_ip).most_common()]

    @property
    def ports(self) -> list[int]:
        """Distinct destination ports, sorted."""
        return sorted({a.dst_port for a in self.alerts if a.dst_port is not None})

    @property
    def source_subnets(self) -> list[str]:
        """Distinct IPv4 source /24 networks, sorted."""
        return sorted({_net(ip).replace("_", ".") + "/24" for ip in self.sources if ":" not in ip})

    def summary(self) -> dict:
        """Compact dict describing the cluster, with lists capped for the report and the LLM."""
        return {
            "id": self.id, "count": self.count, "rules": self.rules[:5], "severity": self.severity,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "sources": self.sources[:10], "source_count": len(self.sources), "source_subnets": self.source_subnets[:5],
            "targets": self.targets[:10], "target_count": len(self.targets), "ports": self.ports[:20],
            "signature": self.representative.signature, "category": self.representative.category,
            "cohesion": self.cohesion,
        }


@dataclass
class ClusterResult:
    """Output of clustering: the meta-alerts plus diagnostics (algorithm, unique documents, silhouette)."""
    meta_alerts: list[MetaAlert]
    algorithm: str
    unique_documents: int
    silhouette: float | None


def _split_sessions(alerts: list[Alert], idx: list[int], window_s: int) -> list[list[int]]:
    """Split member indices (sorted by time) wherever consecutive alerts are more than window_s apart."""
    idx = sorted(idx, key=lambda i: (alerts[i].timestamp, alerts[i].id))
    sessions, current = [], [idx[0]]
    for prev, cur in itertools.pairwise(idx):
        if (alerts[cur].timestamp - alerts[prev].timestamp).total_seconds() > window_s:
            sessions.append(current)
            current = []
        current.append(cur)
    sessions.append(current)
    return sessions


def _kmeans_labels(matrix, weights: np.ndarray, max_k: int, seed: int) -> tuple[np.ndarray, float | None]:
    n = matrix.shape[0]
    if n < 3:
        return np.zeros(n, dtype=int), None
    best: tuple[float, np.ndarray] | None = None
    candidates = sorted({k for k in np.unique(np.geomspace(2, min(max_k, n - 1), num=12).astype(int)) if k >= 2})
    for k in candidates:
        labels = KMeans(n_clusters=k, n_init=4, random_state=seed).fit_predict(matrix, sample_weight=weights)
        if len(set(labels)) < 2:
            continue
        score = float(silhouette_score(matrix, labels, metric="cosine"))
        if best is None or score > best[0]:
            best = (score, labels)
    if best is None:
        return np.zeros(n, dtype=int), None
    return best[1], best[0]


def cluster_alerts(alerts: list[Alert], algorithm: str = "dbscan", eps: float = 0.3, time_window_s: int = 3600,
                   kmeans_max_k: int = 60, seed: int = 7) -> ClusterResult:
    """Cluster alerts into meta-alerts.

    Identical documents are deduplicated and weighted before clustering, so 5,000
    alerts usually collapse to a few hundred vectors. Each cluster is then split
    wherever there is a gap longer than ``time_window_s``.

    Args:
        algorithm: ``dbscan`` (default, eps is a cosine distance) or ``kmeans``
            (k chosen by silhouette, up to ``kmeans_max_k``).
    """
    if not alerts:
        return ClusterResult([], algorithm, 0, None)
    docs = [alert_document(a) for a in alerts]
    unique, inverse = np.unique(np.array(docs, dtype=object), return_inverse=True)
    weights = np.bincount(inverse).astype(float)
    vectorizer = TfidfVectorizer(token_pattern=r"[^ ]+", sublinear_tf=True, lowercase=False)  # noqa: S106
    matrix = vectorizer.fit_transform(unique)          # rows are L2-normalised

    silhouette = None
    if len(unique) == 1:
        unique_labels = np.zeros(1, dtype=int)
    elif algorithm == "kmeans":
        unique_labels, silhouette = _kmeans_labels(matrix, weights, kmeans_max_k, seed)
    else:
        unique_labels = DBSCAN(eps=eps, min_samples=1, metric="cosine").fit_predict(matrix, sample_weight=weights)
        if 1 < len(set(unique_labels)) < len(unique):
            silhouette = float(silhouette_score(matrix, unique_labels, metric="cosine"))
    labels = unique_labels[inverse]

    metas: list[MetaAlert] = []
    for label in sorted(set(labels.tolist())):
        idx = np.flatnonzero(labels == label)
        for members_idx in _split_sessions(alerts, idx.tolist(), time_window_s):
            vecs = matrix[inverse[members_idx]]
            centroid = np.asarray(vecs.mean(axis=0)).ravel()
            norm = np.linalg.norm(centroid)
            sims = (vecs @ (centroid / norm)).ravel() if norm else np.ones(len(members_idx))
            members = [alerts[i] for i in members_idx]
            metas.append(MetaAlert(id="", alerts=members, cohesion=round(float(np.mean(sims)), 4),
                                   representative=alerts[members_idx[int(np.argmax(sims))]],
                                   labels=Counter(a.label for a in members if a.label)))
    metas.sort(key=lambda m: (m.first_seen, m.representative.rule))
    for n, m in enumerate(metas, start=1):
        m.id = f"MA-{n:04d}"
    return ClusterResult(metas, algorithm, len(unique), None if silhouette is None else round(silhouette, 4))
