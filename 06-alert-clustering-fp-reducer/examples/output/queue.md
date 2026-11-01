# Prioritised Alert Queue

Generated 2026-10-27 14:11 UTC from `examples/alerts_simulated.json`. Clustering: dbscan (eps 0.3, session gap 3600s). Triage model: offline / rules-v1.

> **Simulated data.** Every alert in this run was produced by the built-in generator. Figures describe this lab dataset, not a production SOC.

## Summary

| Metric | Value |
|---|---|
| Raw alerts ingested | 5,000 |
| Distinct alert documents | 48 |
| Meta-alerts generated | 19 |
| Suppressed (with reason) | 9 meta-alerts / 3,752 alerts |
| Analyst queue | **10** (6 escalate, 4 investigate) |
| Queue reduction | 99.8% |
| Analyst time, before → after | 333.3 h → 2.0 h (**99.4% saved**) |

Time model: 4.0 min per raw alert vs 12.0 min per enriched meta-alert (set with `TRIAGE_MINUTES_PER_*`).

## Queue

| # | ID | Priority | Action | Alerts | Rule | Severity | Targets | Window (UTC) | Why |
|---|---|---|---|---|---|---|---|---|---|
| 1 | MA-0016 | 83.4 | **escalate** | 1 | Successful SSH login after repeated failures | critical | bastion01 | 10-26 13:24–13:24 | RULES_TRUE_POSITIVE |
| 2 | MA-0015 | 80.2 | **escalate** | 222 | SSH brute force: repeated authentication failures | high | bastion01 | 10-26 13:00–13:23 | RULES_TRUE_POSITIVE |
| 3 | MA-0002 | 75.1 | **escalate** | 133 | ET EXPLOIT Citrix ADC path traversal attempt | high | web03, web01, web02 | 10-26 00:01–23:36 | RULES_TRUE_POSITIVE |
| 4 | MA-0017 | 72.2 | **escalate** | 27 | Kerberoasting: excessive RC4 service ticket requests | high | dc01 | 10-26 14:00–14:11 | RULES_TRUE_POSITIVE |
| 5 | MA-0018 | 67.4 | **escalate** | 3 | Credential dumping: LSASS memory access by unsigned process | critical | ws-fin-015 | 10-26 14:18–14:20 | RULES_TRUE_POSITIVE |
| 6 | MA-0019 | 60.6 | **escalate** | 36 | Outbound connection to threat-intel C2 indicator | high | 203.0.113.200 | 10-26 14:24–15:58 | RULES_TRUE_POSITIVE |
| 7 | MA-0013 | 50.6 | **investigate** | 71 | ET WEB_SERVER SQL injection attempt in query string | medium | app01 | 10-26 10:00–10:29 | NEEDS_REVIEW |
| 8 | MA-0011 | 48.0 | **investigate** | 178 | DNS query for newly registered domain | low | dc01 | 10-26 07:02–17:57 | NEEDS_REVIEW |
| 9 | MA-0014 | 43.6 | **investigate** | 44 | Telnet login attempt to unregistered host | medium | 10.20.9.99 | 10-26 11:00–11:28 | NEEDS_REVIEW |
| 10 | MA-0005 | 31.1 | **investigate** | 533 | Inbound probe to common service ports | low | web01, web02, bastion01 +1 | 10-26 00:04–23:58 | LLM_BENIGN_UNCONFIRMED |

## Meta-alert detail

### MA-0016: Successful SSH login after repeated failures

- **Action:** escalate (priority 83.4, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 1 alert(s) from 1 source(s) to 1 target(s), ports 22
- **Sources:** 198.51.100.77
- **Target bastion01** (10.20.5.50): linux Ubuntu 24.04, SSH bastion, criticality 5, internet-facing; 22/tcp
- **Assessment (offline):** true_positive, confidence 0.70. critical severity activity; treat as real until disproved.
- **Next step:** Escalate to Tier-2 and scope the affected hosts.

### MA-0015: SSH brute force: repeated authentication failures

- **Action:** escalate (priority 80.2, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 222 alert(s) from 1 source(s) to 1 target(s), ports 22
- **Sources:** 198.51.100.77
- **Target bastion01** (10.20.5.50): linux Ubuntu 24.04, SSH bastion, criticality 5, internet-facing; 22/tcp
- **Assessment (offline):** true_positive, confidence 0.60. High-severity detection against a known asset that exposes the targeted service.
- **Next step:** Review the payload and the asset's logs for follow-on activity.

### MA-0002: ET EXPLOIT Citrix ADC path traversal attempt

- **Action:** escalate (priority 75.1, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 133 alert(s) from 102 source(s) to 3 target(s), ports 443
- **Sources:** 198.51.100.6, 198.51.100.155, 198.51.100.163, 198.51.100.80, 198.51.100.30
- **Target web03** (10.20.1.12): linux Debian 12, staff portal, criticality 2, internet-facing; 22/tcp, 443/tcp
- **Target web01** (10.20.1.10): linux Ubuntu 22.04, public website, criticality 3, internet-facing; 22/tcp, 80/tcp, 443/tcp
- **Target web02** (10.20.1.11): linux Ubuntu 22.04, public website, criticality 3, internet-facing; 22/tcp, 80/tcp, 443/tcp
- **Assessment (offline):** true_positive, confidence 0.60. High-severity detection against a known asset that exposes the targeted service.
- **Next step:** Review the payload and the asset's logs for follow-on activity.

### MA-0017: Kerberoasting: excessive RC4 service ticket requests

- **Action:** escalate (priority 72.2, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 27 alert(s) from 1 source(s) to 1 target(s), ports 88
- **Sources:** 10.30.10.15 (internal: ws-fin-015)
- **Target dc01** (10.20.4.40): windows Server 2022, domain controller, criticality 5; 53/tcp, 88/tcp, 389/tcp, 445/tcp, 3389/tcp
- **Assessment (offline):** true_positive, confidence 0.70. high severity activity from an internal asset; treat as real until disproved.
- **Next step:** Escalate to Tier-2 and scope the affected hosts.

### MA-0018: Credential dumping: LSASS memory access by unsigned process

- **Action:** escalate (priority 67.4, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 3 alert(s) from 1 source(s) to 1 target(s), ports n/a
- **Sources:** 10.30.10.15 (internal: ws-fin-015)
- **Target ws-fin-015** (10.30.10.15): windows Windows 11 23H2, finance workstation, criticality 3; 135/tcp, 445/tcp
- **Assessment (offline):** true_positive, confidence 0.70. critical severity activity from an internal asset; treat as real until disproved.
- **Next step:** Escalate to Tier-2 and scope the affected hosts.

### MA-0019: Outbound connection to threat-intel C2 indicator

- **Action:** escalate (priority 60.6, reason `RULES_TRUE_POSITIVE`)
- **Volume:** 36 alert(s) from 1 source(s) to 1 target(s), ports 443
- **Sources:** 10.30.10.15 (internal: ws-fin-015)
- **Not in CMDB:** 203.0.113.200
- **Assessment (offline):** true_positive, confidence 0.70. high severity activity from an internal asset; treat as real until disproved.
- **Next step:** Escalate to Tier-2 and scope the affected hosts.

### MA-0013: ET WEB_SERVER SQL injection attempt in query string

- **Action:** investigate (priority 50.6, reason `NEEDS_REVIEW`)
- **Volume:** 71 alert(s) from 2 source(s) to 1 target(s), ports 8443
- **Sources:** 203.0.113.45, 203.0.113.46
- **Target app01** (10.20.2.20): linux RHEL 9, student records API, criticality 4, internet-facing; 22/tcp, 8443/tcp
- **Assessment (offline):** needs_investigation, confidence 0.50. Rules cannot decide this cluster without analyst review.
- **Next step:** Review a sample of the clustered alerts.

### MA-0011: DNS query for newly registered domain

- **Action:** investigate (priority 48.0, reason `NEEDS_REVIEW`)
- **Volume:** 178 alert(s) from 30 source(s) to 1 target(s), ports 53
- **Sources:** 10.30.10.11, 10.30.10.17, 10.30.10.10, 10.30.10.5, 10.30.10.26 (internal: ws-fin-015, mac-design-022)
- **Target dc01** (10.20.4.40): windows Server 2022, domain controller, criticality 5; 53/tcp, 88/tcp, 389/tcp, 445/tcp, 3389/tcp
- **Assessment (offline):** needs_investigation, confidence 0.50. Rules cannot decide this cluster without analyst review.
- **Next step:** Review a sample of the clustered alerts.

### MA-0014: Telnet login attempt to unregistered host

- **Action:** investigate (priority 43.6, reason `NEEDS_REVIEW`)
- **Volume:** 44 alert(s) from 14 source(s) to 1 target(s), ports 23
- **Sources:** 10.40.0.10, 10.40.0.5, 10.40.0.7, 10.40.0.3, 10.40.0.13
- **Not in CMDB:** 10.20.9.99
- **Assessment (offline):** needs_investigation, confidence 0.50. 1 target(s) are not in the CMDB, so the attack surface is unknown.
- **Next step:** Identify the owner of the unknown hosts and register them.

### MA-0005: Inbound probe to common service ports

- **Action:** investigate (priority 31.1, reason `LLM_BENIGN_UNCONFIRMED`)
- **Volume:** 533 alert(s) from 390 source(s) to 4 target(s), ports 21, 23, 25, 80, 110, 143, 443, 3306, 5900, 6379
- **Sources:** 192.0.2.182, 198.51.100.21, 203.0.113.196, 192.0.2.23, 198.51.100.28
- **Target web01** (10.20.1.10): linux Ubuntu 22.04, public website, criticality 3, internet-facing; 22/tcp, 80/tcp, 443/tcp
- **Target web02** (10.20.1.11): linux Ubuntu 22.04, public website, criticality 3, internet-facing; 22/tcp, 80/tcp, 443/tcp
- **Target bastion01** (10.20.5.50): linux Ubuntu 24.04, SSH bastion, criticality 5, internet-facing; 22/tcp
- **Assessment (offline):** benign_true_positive, confidence 0.60. External scanning of internet-facing assets is expected background activity.
- **Next step:** Confirm the scanned ports match the published services.
- **Flags:** guardrail:confidence 0.60 &lt; 0.80, asset criticality 5 &gt;= 4

## Suppressed

Every suppression is listed with its evidence so it can be audited or reversed.

| ID | Alerts | Rule | Reason | Evidence |
|---|---|---|---|---|
| MA-0007 | 1600 | ET SCAN Nmap SYN scan | `AUTHORIZED_SCANNER` | all 2 source(s) are registered scanners: secops-vuln-mgmt (weekly authenticated vulnerability scan) |
| MA-0004 | 622 | ET EXPLOIT Possible BlueKeep RDP exploitation attempt | `STRUCTURAL_FP` | attack cannot succeed on any of the 3 target(s) [rdp]: targets windows but web02 runs linux; targets windows but web03 runs linux; targets windows but web01 runs linux |
| MA-0006 | 356 | ET EXPLOIT EternalBlue SMB exploitation attempt | `STRUCTURAL_FP` | attack cannot succeed on any of the 4 target(s) [smb]: targets windows but app01 runs linux; targets windows but web03 runs linux; targets windows but web02 runs linux |
| MA-0008 | 356 | ET SCAN Nessus User-Agent observed | `AUTHORIZED_SCANNER` | all 1 source(s) are registered scanners: secops-vuln-mgmt (weekly authenticated vulnerability scan) |
| MA-0001 | 267 | GPL RDP brute force login attempts | `STRUCTURAL_FP` | attack cannot succeed on any of the 3 target(s) [rdp]: targets windows but web01 runs linux; targets windows but web03 runs linux; targets windows but web02 runs linux |
| MA-0003 | 267 | ET WEB_SERVER IIS WebDAV exploitation attempt | `STRUCTURAL_FP` | attack cannot succeed on any of the 2 target(s) [iis]: targets windows but web02 runs linux; targets windows but web01 runs linux |
| MA-0012 | 178 | ET WEB_SPECIFIC_APPS Apache Struts2 OGNL injection attempt | `STRUCTURAL_FP` | attack cannot succeed on any of the 1 target(s) [struts]: needs struts but iis01 does not run it |
| MA-0009 | 53 | Configuration file modified on database server | `MAINTENANCE_WINDOW` | every target was in a maintenance window: CHG-20431 PostgreSQL minor upgrade and reboot |
| MA-0010 | 53 | PostgreSQL service stopped unexpectedly | `MAINTENANCE_WINDOW` | every target was in a maintenance window: CHG-20431 PostgreSQL minor upgrade and reboot |

## Evaluation against ground truth

| Measure | Value |
|---|---|
| True-threat recall (alerts) | 100.00% |
| Suppression precision | 100.00% |
| Noise removed | 81.64% |
| Cluster purity | 100.00% |
| Suppressed meta-alerts containing a true positive | none |
| Escalated meta-alerts that are noise | MA-0002 |
