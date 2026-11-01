# Case studies

These write-ups show how I investigate an alert and how I improve a detection, using the portfolio's own tools. Each one starts with a table that says which parts are real (code, runs and output) and which are simulated (event recordings and test payloads). None of it has been run against a live production environment.

| # | Case study | What it shows |
|---|---|---|
| 01 | [Macro document to mass file modification on a finance share](01-maldoc-to-ransomware-investigation.md) | Investigating the [03 EDR sensor](../../03-edr-canary-process-tree/)'s maldoc-to-ransomware replay: initial alert, raw evidence, timeline, queries, alternative explanations, disposition and response rationale, plus what the sensor missed |
| 02 | [Improving encoded PowerShell detection](02-encoded-powershell-detection-improvement.md) | One detection improvement with before-and-after evidence: the missed behaviour, the rule change (EDR-PT-005), benign regression cases, severity reasoning and the known gaps that remain |

Every number and alert in these documents can be reproduced offline from `03-edr-canary-process-tree/` with the commands at the end of each one.
