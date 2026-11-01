# Architecture Defense Index

Projects 01 to 06 and Watchfloor document their design in a `docs/ARCHITECTURE.md` with the same structure (07 to 10 keep the same content in their READMEs, under "How it works", "Safety" and "Limits"):

1. The SOC problem it solves.
2. A data-flow diagram.
3. A decision table: concern, decision, and why. It names the specific algorithms and libraries and the alternatives rejected.
4. Limits and next steps.

| Project | Core problem | Key design choices | Document |
|---|---|---|---|
| 01 Real-time AI-SIEM | Raw syslog is unstructured, and single alerts lack the story | asyncio UDP receiver; strict ECS 8.11 mapping; sliding-window detections; chain correlation by source IP; Claude summaries with data fencing, a JSON schema, a token bucket and a circuit breaker; offline fallback | [ARCHITECTURE.md](../01-realtime-ai-siem/docs/ARCHITECTURE.md) |
| 02 HitL SOAR bot | Automated containment without a human check is a liability | signature-verified callbacks (Slack HMAC-SHA256, Discord Ed25519); durable SQLite state machine; exactly-once remediation; audit trail; MTTA and MTTR timing | [ARCHITECTURE.md](../02-hitl-soar-bot/docs/ARCHITECTURE.md) |
| 03 EDR canary and process tree | Office-spawned shells and ransomware touching files are caught too late | Kernel ETW via TraceEvent (pinned SHA-256); live process tree with ancestry search; canary tripwires; guarded suspend and containment with `-WhatIf` | [ARCHITECTURE.md](../03-edr-canary-process-tree/docs/ARCHITECTURE.md) |
| 04 Blast-radius scanner | CVSS-sorted lists ignore exploitation likelihood and network position | NVD 2.0 CPE matching; EPSS and KEV; NetworkX reachability; Dijkstra on −log(likelihood); blast radius with hop decay; chokepoints; SARIF | [ARCHITECTURE.md](../04-blast-radius-vuln-scanner/docs/ARCHITECTURE.md) |
| 05 Sigma ATT&CK coverage | "We'd catch that" is an assumption, not a measurement | Built-in Sigma engine (modifiers and full condition grammar); Sysmon, 4688 and ECS normalisation; host-plus-time attribution; DETECTED, DETECTION_GAP, TELEMETRY_GAP and NO_CONTENT outcomes; Navigator layer | [ARCHITECTURE.md](../05-sigma-attack-coverage/docs/ARCHITECTURE.md) |
| 06 Alert clustering and FP reducer | Alert fatigue: duplicates and inapplicable signatures bury real threats | TF-IDF over behaviour tokens; cosine DBSCAN with sample weights; SQLite CMDB; declarative structural-FP requirements; guarded Claude triage with cache; recall-gated CI | [ARCHITECTURE.md](../06-alert-clustering-fp-reducer/docs/ARCHITECTURE.md), [Operational efficiency report](../06-alert-clustering-fp-reducer/docs/OPERATIONAL_EFFICIENCY_REPORT.md) |
| Watchfloor hub | Ten tools, ten formats, no single view of an incident | OCSF 1.4.0 at the edge (mappers per source, JSON Schemas); Redis Streams with a consumer group that acks only after the Parquet rename; hive-partitioned Parquet read by DuckDB with fixed SQL; FastAPI hub; React console with a static replay build | [ARCHITECTURE.md](../watchfloor/docs/ARCHITECTURE.md) |
| 07 Attack emulator | Coverage claims go stale the day they are measured | Atomic Red Team picked by test name; kubectl, WinRM, SSH, replay and dry-run executors; lab CIDR and kube-context guard rails with explicit opt-in; backoff with full jitter; six verdicts including prevented and error; Navigator layer | [README](../07-attack-emulator/README.md#how-scoring-works) |
| 08 Detection rules | 05's engine measured gaps; something has to close them on live data | Unmodified Sigma rules; pySigma with a custom OCSF pipeline and DuckDB backend; `ILIKE ... ESCAPE` with `coalesce(..., false)` so `not` filters survive missing fields; per-rule match/no-match samples gate the build; watermark plus overlap with stable finding ids | [README](../08-detection-rules/README.md#why-a-custom-backend) |
| 09 Evidence timeline | Evidence on an approved host is collected late or not at all | Starts only on a signed request after 02's approval; Velociraptor gRPC with VQL parameters (no string building); read-only artifact allowlist; Hayabusa plus hub telemetry merged into one timeline; atomic packages with a SHA-256 manifest | [README](../09-evidence-timeline/README.md#safety) |
| 10 AI analyst | An LLM between attacker-controlled logs and the on-call analyst | Eight read-only MCP tools with typed, bounded arguments; locked DuckDB and read-only SQLite; results wrapped as untrusted data; citations checked against the cited result; confidence caps; Claude, Ollama or offline rules behind one session; injection evals in CI | [Threat model](../10-ai-analyst-mcp/docs/THREAT_MODEL.md) |
| n8n playbooks | Glue between detection, approval and collection without moving the approval out of 02 | n8n orchestrates, 02 decides; every hop HMAC-signed with its own secret over the raw body; Code nodes kept as files and tested under Node against the Python verifiers | [README](../automation/n8n/README.md) |
| Detection lab | Emulation needs targets that produce the same telemetry as production | Vagrant VMs on a host-only network; Ansible with address and checksum guards; microK8s with Tetragon TracingPolicies; Sysmon, 03's canary and Fluent Bit on Windows; Velociraptor client | [README](../lab/README.md) |

## Cross-cutting decisions

| Concern | Decision | Why |
|---|---|---|
| Isolation | One directory per project, each with its own dependencies, tests and `.env.example` | Each project can be reviewed, deployed or deleted on its own. A dependency bump in one cannot break another. |
| Schema | ECS for every alert that leaves 01 to 06; OCSF 1.4.0 on the Watchfloor spine, with mappers at the edge | The original projects keep their tested formats. OCSF is vendor-neutral and class-based, which suits a lake queried by class, and Security Lake, Splunk and Sentinel all speak it. |
| Containment | Only 02 can start it, only after a signed human click. The console, n8n and the analyst can only *request* an approval | One choke point to audit. A compromised playbook, a prompt-injected model or a stolen console token cannot isolate a host. |
| Integration | Signed webhooks (HMAC over timestamp and raw body, 300 s skew, replay cache) with a separate secret per hop | A leaked secret affects one hop; replays and tampering are refused; the same verifier code is reused and cross-tested. |
| Data access | DuckDB in-process over Parquet; read-only consumers (08, 10) get the lake mounted read-only | No database server to run or secure, and the readers cannot change evidence. |
| LLM use | Claude explains and advises, while deterministic code decides. Every call has an offline fallback | An API outage or a prompt-injected alert must never cause a missed detection or a silent suppression. |
| Secrets | Environment and dotenv only. gitleaks runs in CI and `.env` is never committed | Credentials in code are the most common avoidable breach in security tooling itself. |
| Quality gates | ruff with security rules, an 85% coverage floor, and content tests (Sigma cases, a recall gate) | Detection logic is code and gets the same rigour as code. |
