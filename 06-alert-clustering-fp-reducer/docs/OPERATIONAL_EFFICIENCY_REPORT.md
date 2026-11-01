# Operational Efficiency Report: Contextual Alert Triage

**Audience:** SOC leadership and security operations management
**Subject:** Reducing alert fatigue with clustering, asset context and AI-assisted false-positive analysis
**Evidence base:** Published industry surveys (cited inline) and a reproducible run of Project 06 on simulated data (section 4)

---

## 1. The alert fatigue crisis

Alert volume has outgrown the people who triage it. The surveys below come from vendor-sponsored research, so the exact figures should be read with that in mind. They point the same way, though, across different years, sponsors and samples:

| Finding | Source |
|---|---|
| SOC teams receive **4,484 alerts a day** on average. **67%** of them are not dealt with, and analysts spend nearly **three hours a day** on manual triage | Vectra AI, *2023 State of Threat Detection*, 2,000 security analysts ([summary](https://www.intelligentcio.com/north-america/2023/08/04/research-reveals-significant-disconnect-between-security-operations-teams-and-the-effectiveness-of-threat-detection/), [report](https://content.vectra.ai/hubfs/downloadable-assets/V_2023-State-of-Threat-Detection.pdf)) |
| The same study reports an **83%** figure for alerts being false positives and not worth analysts' time, and **67%** of analysts considering leaving or actively leaving their jobs | Vectra AI, 2023 (as above) |
| **45%** of alerts handled by in-house SOC teams are false positives (**53%** for MSSPs). **35%** of in-house analysts (**44%** at MSSPs) admit ignoring alerts when the queue is too full. Three in four worry about missing incidents | IDC InfoBrief for FireEye, *The Voice of the Analysts*, 350 respondents, surveyed Fall 2020 ([press release](https://www.businesswire.com/news/home/20210216005436/en/Automating-Threat-Detection-Desired-for-Security-Analysts-Battling-Fear-of-Missing-Incidents-and-Security-Operations-Center-Inefficiency/), [coverage](https://www.securitysales.com/business/industry/fireeye-soc-report-alert-fatigue/)) |
| **71%** of SOC analysts report burnout and **64%** are considering leaving for a new job. **64%** say manual work takes more than half their time | Tines survey of 468 SOC analysts, reported by [Dark Reading](https://darkreading.com/threat-intelligence/more-than-70-of-soc-analysts-experiencing-burnout) |
| **65%** of security practitioners have considered quitting. "Too many false positives" is cited as a reason threat hunting and investigation fail | Ponemon Institute for Devo, *Improving the Effectiveness of the SOC*, 554 respondents, 2019 ([press release](https://www.devo.com/company/newsroom/ponemon-institute-and-devo-technology-study-reveals-65-of-cybersecurity-analysts-consider-quitting-due-to-burnout-lack-of-visibility/)) |

What this costs is not "analyst time". It is **missed incidents and lost people**:

- When two-thirds of alerts are never looked at, the one that matters is triaged by chance.
- When analysts leave within a year or two, the tribal knowledge leaves with them: which scanner is ours, which servers are Linux, and which signatures always misfire. That knowledge is exactly what makes triage fast.

## 2. Why static rules cannot fix it

The usual responses each trade one failure for another:

- **Tuning rules down** (raising thresholds, disabling noisy signatures) removes the noise everywhere, including the one asset where the signature *is* applicable. Disabling BlueKeep detection because the web tier is Linux also blinds you on the Windows jump hosts.
- **Static suppression lists** (ignore source X, ignore rule Y on subnet Z) go stale the moment the estate changes. Nobody owns them, they are rarely reviewed, and attackers who learn them get a free pass.
- **Per-alert SOAR playbooks** automate the *handling* of each alert but keep its *count*. Five hundred automated enrichments of the same port scan still create five hundred tickets.
- **The SIEM rule has no context.** It knows the packet matched a pattern. It does not know the target is a Linux web server with no listener on 3389. That fact lives in the CMDB, which is a different system owned by a different team.

The underlying issue is that **applicability is a property of the target, not of the signature**. Applicability means whether an attack can succeed at all. Fixing it at the rule layer is the wrong place.

## 3. Enrichment architecture

Project 06 adds a contextual layer between the SIEM and the ticketing system. The design is in [ARCHITECTURE.md](ARCHITECTURE.md). In outline:

1. **Collapse volume first.**
   - TF-IDF over typed behaviour tokens (rule, category, source and destination /24, port, signature words).
   - DBSCAN with cosine distance merges near-duplicates into meta-alerts.
   - Scans are treated as sweeps, so 1,600 authorised Nmap alerts become **one** meta-alert.
   - Clusters split on quiet gaps, so a repeat next week is a new incident.
2. **Enrich from the CMDB.** Each meta-alert is joined to the asset records of its targets and sources: OS, listening services, role, criticality 1–5, internet exposure, registered scanner ranges and change windows.
3. **Decide deterministically where the facts allow.** A reviewed requirements file states what each attack family needs. For example, RDP attacks need Windows and 3389, and Struts attacks need Struts. If **every** target lacks it, the cluster is a *structural false positive*: the attack cannot technically succeed. Unknown assets are never dismissed.
4. **Use the LLM for the long tail.**
   - Claude receives the undecided clusters only, with asset context and the strict structural rule from the brief.
   - It returns a schema-constrained verdict.
   - A policy guardrail decides whether that verdict may suppress anything: confidence, criticality, severity and completeness of context.
   - Structural findings are fed back as suggested requirements, so the deterministic layer keeps growing.
5. **Rank what is left.** Severity, asset criticality, exposure, volume and spread give a 0–100 priority. Every suppression is reported with its evidence.

This puts each decision where the evidence lives: facts in the CMDB, judgement in the model, and policy in code.

## 4. Metrics and ROI (simulated)

> **These figures come from simulated data.** The run used the project's seeded generator (`generate --count 5000 --seed 7`) against a 12-asset mock CMDB, in offline mode (no LLM). They demonstrate the mechanism and are reproducible. They are **not** a measurement of any production SOC. Real-world reduction depends on how noisy the detection content is and how complete the CMDB is.

### Pipeline result

| Stage | Value |
|---|---|
| Raw alerts ingested | **5,000** |
| Distinct behaviour documents | 48 |
| Meta-alerts generated | **19** |
| Suppressed with evidence | 9 meta-alerts covering 3,752 alerts (75.0%) |
| Analyst queue | **10** meta-alerts (6 escalate, 4 investigate) |
| Tickets per day | 5,000 → 10 (**99.8% fewer**) |
| True-threat recall (labelled) | **100%**: all 404 true-positive alerts reached the queue |
| Suppression precision | **100%**: nothing suppressed was a true positive |
| Noise removed | 81.6% of false-positive and benign alerts |
| Cluster purity | 100% |

Suppressed, by reason:

| Reason | Meta-alerts | Alerts | Example evidence |
|---|---|---|---|
| Structural false positive | 5 | 1,690 | "targets windows but web01 runs linux" (BlueKeep, RDP brute force, EternalBlue, IIS WebDAV, Struts against IIS) |
| Authorised scanner | 2 | 1,956 | "registered scanners: secops-vuln-mgmt (weekly authenticated vulnerability scan)" |
| Maintenance window | 2 | 106 | "CHG-20431 PostgreSQL minor upgrade and reboot" |

The deterministic layer alone did this, at zero API cost. With Claude enabled, the remaining Citrix-against-nginx cluster (133 alerts, a structural mismatch the requirements file does not yet cover) is the expected next suppression. The internet background-scan cluster would move from "investigate" to a low-priority benign label.

### Analyst time

The time saved depends on assumptions. They are made explicit here and are configurable (`TRIAGE_MINUTES_PER_*`):

| Scenario | Before | After | Saved |
|---|---|---|---|
| Default model: 4 min per raw alert, 12 min per enriched meta-alert | 5,000 × 4 min = 333 h | 10 × 12 min = 2.0 h | **99.4%** |
| Conservative: 1 min per raw alert (bulk-closing duplicates), 30 min per meta-alert | 83 h | 5.0 h | **94.0%** |
| Very conservative: only the third of alerts that surveys say gets looked at is triaged today (1,650 at 1 min), 30 min per meta-alert | 27.5 h | 5.0 h | **81.8%** |

The 333-hour baseline exceeds any team's capacity, and that is the point. Today those alerts are not triaged. They are ignored, which is what the 67% and 35–44% figures in section 1 describe. So the real return is not only hours. It is **coverage**: every behaviour in the day's data gets a decision, and the 404 true-positive alerts reach an analyst as 7 entries in a 10-item queue, not as 404 lines among 5,000.

### Return beyond hours

- **Lower missed-incident risk.** The brute-force-then-login chain on the bastion ranks first and second, and credential dumping on a finance workstation is in the top five, rather than sitting among 1,600 scan alerts.
- **Retention.** Repetitive bulk-closing is the work that analysts in the surveys above say burns them out. Removing it is the lever the surveys point to.
- **Auditability.** Each suppression is a recorded, reviewable decision with evidence. A silent "closed – noise" is not.
- **Controlled AI cost.** The model sees about 10 behaviours per day, not 5,000 alerts. Verdicts are cached, and an outage degrades to deterministic-only triage.

## 5. Recommendations

1. **Pilot in shadow mode** for two weeks. Run the engine beside the existing queue, and compare its suppressions with analyst decisions to measure real precision and recall.
2. **Wire the CMDB to discovery.** Populate services from authenticated scans (Project 04's Nmap ingestion), so structural decisions rest on observed facts.
3. **Govern the requirements file as detection content.** Peer review it, version it, and test it in CI like Sigma rules (Project 05).
4. **Sample suppressed clusters weekly** to keep measuring the false-negative rate after go-live.
5. **Enable Claude after the shadow period.** Keep the guardrail at a confidence of 0.8 or higher with the criticality ceiling at 4, and promote its suggested requirements through review.
