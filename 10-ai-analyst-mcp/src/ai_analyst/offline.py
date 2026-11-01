"""The offline analyst: a fixed investigation plan and explicit rules, through the same tools and guards.

It is deliberately simple and fully explainable. It exists so the pipeline (tools, budgets, citations, transcripts,
console) runs and is tested without an API key, and as the baseline the eval suite compares models against.
"""

from __future__ import annotations

from typing import Any

from .engine import ToolSession

# Parent techniques that mean real attacker activity when a high-severity detection carries them.
SEVERE = {"T1003", "T1021", "T1036", "T1053", "T1059", "T1078", "T1105", "T1110", "T1136", "T1218", "T1486",
          "T1485", "T1490", "T1543", "T1548", "T1566", "T1204"}
DISCOVERY = {"T1046", "T1595", "T1590", "T1018", "T1135"}
HOUR = 3600_000


def _parent(t: str) -> str:
    return t.split(".", 1)[0]


class OfflineProvider:
    """Deterministic rule-based analyst: calls the same tools a model would and cites what they returned."""
    name = "offline"
    model = "rules-v1"

    def run(self, session: ToolSession, system: str, task: str, incident_id: str) -> None:
        ev: list[dict[str, str]] = []

        def cite(call_id: str, quote: Any) -> None:
            q = str(quote or "").strip()
            if call_id and len(q) >= 3 and not any(e["quote"] == q[:300] for e in ev):
                ev.append({"tool_call": call_id, "quote": q[:300]})

        c_inc, _, err = session.call("get_incident", {"incident_id": incident_id})
        if err:
            session.submit({"verdict": "needs_more_data", "confidence": 0.1, "evidence": [
                {"tool_call": c_inc, "quote": session.results[c_inc]["error"]}],
                "summary": f"Incident {incident_id} could not be loaded from the lake.", "recommended_actions": []})
            return
        data = session.results[c_inc]
        inc = data["incident"]
        host, at, ip = inc.get("host"), int(inc["detected_at_ms"]), inc.get("indicator_ip")
        cite(c_inc, inc["title"])
        findings: dict[str, tuple[str, dict[str, Any]]] = {
            f["uid"]: (c_inc, f) for f in (data.get("related_findings") or {}).get("rows", [])}

        asset, maint, c_asset = None, None, ""
        if host:
            c_asset, _, err = session.call("lookup_asset", {"hostname": host, "at_ms": at})
            res = session.results[c_asset]
            if not err and res.get("found"):
                asset, maint = res["asset"], res.get("maintenance_at_time")
        scanner, ip_info, auth, c_ip, c_auth = None, None, [], "", ""
        if ip:
            c_ip, _, err = session.call("check_ip", {"ip": ip})
            if not err:
                ip_info = session.results[c_ip]
                scanner = ip_info.get("authorized_scanner")
            c_auth, _, err = session.call("auth_summary", {"since_ms": max(0, at - 6 * HOUR), "until_ms": at + HOUR,
                                                           "src_ip": ip})
            if not err:
                auth = session.results[c_auth]["rows"]
        if host:
            c_f, _, err = session.call("get_findings", {"hostname": host, "since_ms": max(0, at - 2 * HOUR),
                                                        "until_ms": at + HOUR})
            if not err:
                for f in session.results[c_f]["rows"]:
                    findings.setdefault(f["uid"], (c_f, f))
        ranked = sorted(findings.values(), key=lambda cf: (-int(cf[1]["severity_id"] or 0), cf[1]["time"]))
        chain: list[dict[str, Any]] = []
        c_chain = ""
        with_pid = next((f for _, f in ranked if f.get("process_pid") is not None and f.get("hostname")), None)
        if with_pid:
            c_chain, _, err = session.call("process_ancestry", {"hostname": with_pid["hostname"],
                                                                "pid": int(with_pid["process_pid"]),
                                                                "at_ms": int(with_pid["time"])})
            if not err:
                chain = session.results[c_chain]["ancestry"]

        techniques = sorted({t for _, f in ranked for t in (f.get("techniques") or [])})
        parents = {_parent(t) for t in techniques}
        high = [f for _, f in ranked if int(f["severity_id"] or 0) >= 4]
        max_sev = max((int(f["severity_id"] or 0) for _, f in ranked), default=0)
        fails = sum(r["attempts"] for r in auth if r["outcome"] == "failure")
        wins = [r for r in auth if r["outcome"] == "success"]

        # The decision, most specific explanation first.
        if scanner and parents and parents <= DISCOVERY:
            verdict, conf = "benign_true_positive", 0.8
            cite(c_ip, scanner["purpose"])
            cite(c_ip, scanner["owner"])
            why = (f"The source {ip} is inside the authorised scanner range {scanner['cidr']} owned by "
                   f"{scanner['owner']} ({scanner['purpose']}), and the detections are discovery only.")
        elif maint and max_sev <= 3:
            verdict, conf = "benign_true_positive", 0.7
            cite(c_asset, maint["reason"])
            why = (f"A maintenance window was open on {host} at the time ({maint['reason']}) and no detection was "
                   "above medium severity.")
        elif high and (len(high) >= 2 or parents & SEVERE):
            verdict = "true_positive"
            conf = min(0.95, 0.6 + 0.07 * len(parents & SEVERE) + (0.05 if wins and fails else 0))
            why = (f"{len(high)} high or critical detections on {host} line up into one chain"
                   f" ({', '.join(techniques)}), which does not fit any authorised activity in the CMDB.")
        else:
            verdict, conf = "needs_more_data", 0.35 if findings else 0.25
            why = ("The only signal is low severity and nothing corroborates it: no related detections, no "
                   "suspicious authentication, no maintenance or scanner record that explains it.")
        for c, f in ranked[:4]:
            cite(c, f["finding_title"])
        if asset:
            cite(c_asset, asset["role"])
        for p in chain[1:3]:
            cite(c_chain, p["process_name"])
        if wins and fails:
            cite(c_auth, wins[0]["user_name"])
        for flag in session.flags[:2]:
            cite(flag["tool_call"], flag["excerpt"])
        if not ev:
            cite(c_inc, inc["id"])

        parts = [f"{inc['title']} on {host or 'an unknown host'}"
                 + (f" ({asset['role']}, criticality {asset['criticality']}, owner {asset['owner']})." if asset
                    else ", which is not in the CMDB.")]
        if ranked:
            first, last = ranked[0][1], ranked[-1][1]
            times = sorted(f["time_utc"][11:19] for _, f in ranked)
            parts.append(f"{len(ranked)} detection findings between {times[0]} and {times[-1]} UTC"
                         + (f" cover {', '.join(techniques)}." if techniques else ".")
                         + (f" The most severe is \"{first['finding_title']}\"." if first is not last else ""))
        if chain:
            names = " → ".join(p["process_name"] for p in reversed(chain) if p.get("process_name"))
            parts.append(f"Process chain: {names}.")
        if ip and ip_info:
            parts.append(f"Source {ip} is a {ip_info['scope']} address"
                         + (f" with {fails} failed and {sum(r['attempts'] for r in wins)} successful logins around "
                            "the incident." if auth else "."))
        parts.append(why)
        if session.flags:
            parts.append("Some log text reads like instructions to the analyst; it was treated as data and may be "
                         "an attempt to tamper with triage.")
        if inc.get("status"):
            parts.append(f"In the SOAR bot the incident is {inc['status'].replace('_', ' ')}"
                         + (f" (decided by {inc['decided_by']})." if inc.get("decided_by") else "."))
        session.submit({"verdict": verdict, "confidence": round(conf, 2), "summary": " ".join(parts),
                        "evidence": ev[:12], "recommended_actions": self._actions(verdict, inc, ip_info, scanner,
                                                                                 maint, techniques, wins, fails)})

    @staticmethod
    def _actions(verdict: str, inc: dict[str, Any], ip_info: dict[str, Any] | None, scanner: dict[str, Any] | None,
                 maint: dict[str, Any] | None, techniques: list[str], wins: list[dict[str, Any]], fails: int
                 ) -> list[str]:
        host, status = inc.get("host"), inc.get("status")
        out: list[str] = []
        if verdict == "true_positive":
            if status == "awaiting_approval":
                out.append(f"Approve the pending isolation of {host} in the SOAR bot; it is still waiting for a "
                           "decision.")
            elif status in ("remediated", "approved"):
                out.append(f"Keep {host} isolated until the evidence package for {inc['id']} has been reviewed.")
            if wins and fails:
                users = sorted({r["user_name"] for r in wins if r.get("user_name")})
                out.append(f"Reset the password of {', '.join(users)} and review every session it opened.")
            if ip_info and ip_info["scope"] in ("public", "documentation") and not ip_info.get("asset"):
                out.append(f"Block {ip_info['ip']} at the perimeter; it is external and not in the CMDB.")
            if any(t.startswith(("T1486", "T1485")) for t in techniques):
                out.append("Restore the modified files from backup after the host is rebuilt, and check the "
                           "shares it could write to.")
            if techniques:
                out.append(f"Hunt for {', '.join(techniques[:4])} on other hosts in the same window.")
        elif verdict == "benign_true_positive":
            if scanner:
                out.append(f"Close as authorised scanning by {scanner['owner']}, and tune the rule to exclude "
                           f"{scanner['cidr']}.")
            if maint:
                out.append(f"Close as planned change ({maint['reason']}); confirm with the change owner.")
        else:
            out.append(f"Collect process and network telemetry from {host or 'the host'} around the detection "
                       "before deciding.")
            out.append("Ask the asset owner whether the activity was expected.")
        return out
