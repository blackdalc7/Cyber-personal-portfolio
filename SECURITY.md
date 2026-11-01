# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's **private vulnerability reporting** (Security → Report a vulnerability) on this repository. Include the affected project, the version or commit, reproduction steps and the impact. You can expect an acknowledgement within 5 working days and a fix or mitigation plan within 30 days.

## Scope and intended use

Every project in this repository is **defensive**:

- 01, 03, 06 and 08 detect and triage. 04, 05 and 07 measure exposure and detection coverage. 09 collects evidence read-only. 10 explains incidents with read-only tools. Watchfloor and the n8n playbooks connect them.
- Active response is opt-in and human-gated. 02 isolates a host only after a signed analyst approval, and it is the only component that can. The console's isolate button, the n8n playbooks and the AI analyst can at most *request* an approval card. 03 contains only with `EDR_AUTO_CONTAIN` explicitly enabled, and it honours `-WhatIf`.
- Simulations (`replay`, `Invoke-SafeSimulation`, `alert-triage generate`, 07's replay executor) produce recorded or synthetic *telemetry*. No project ships exploits, payloads or offensive tooling.
- 07 runs public Atomic Red Team tests, and only against the isolated lab: every target must be an IP inside `LAB_ALLOWED_CIDRS` (nothing wider than a /16), every kube context must be allowlisted and point inside those ranges, and a live run needs `--confirm-lab`. The lab VMs live on a host-only network; never bridge them to a real LAN.
- 09 runs only read-only Velociraptor artifacts from an allowlist; names suggesting remediation, deletion, shells or uploads are refused at start-up.
- Example data uses RFC 1918 and RFC 5737 documentation address ranges.

Run 04's active Nmap scanning only against networks you are authorised to test.

## Secrets

- Credentials are read only from environment variables, or from a local `.env` loaded with python-dotenv. `.env` is git-ignored. Each project ships a `.env.example` with empty values.
- CI runs gitleaks on the full history and fails if any `.env` file is tracked.
- Every signed hop has its own secret (`WEBHOOK_SHARED_SECRET`, `DECISION_WEBHOOK_SECRET`, `EVIDENCE_SHARED_SECRET`), at least 32 characters; 02 refuses to start if the decision secret equals the alert secret.
- Lab downloads (Sysmon, Fluent Bit, the Velociraptor client and server binaries) are pinned by SHA-256, and the playbooks stop while a checksum is empty.
- LLM API keys are read by the Anthropic SDK and are never logged or written to output.

## Supply chain

- Python dependencies have bounded version ranges and are audited with `pip-audit` in CI. The PowerShell TraceEvent package is verified against a pinned SHA-256.
- Dependabot tracks pip, Docker base images and GitHub Actions weekly.
- Containers run as a non-root user. The platform compose file (`deploy/`) gives every service a read-only root filesystem, `cap_drop: [ALL]` and `no-new-privileges`, binds every port to 127.0.0.1 unless told otherwise, and mounts the lake read-only into every reader.

## Handling untrusted input

Log lines, alert fields, scan XML and rule files are treated as attacker-controlled:

- XML is parsed with defusedxml, so XXE and entity expansion are rejected.
- YAML is loaded with `safe_load` only.
- SQL is always parameterised.
- Data sent to an LLM is fenced, its closing tags are escaped, and the response is schema-constrained.
- The AI analyst (10) has read-only tools only, a locked DuckDB connection and a read-only CMDB; its evidence quotes are checked against the tool results they cite, and a benign verdict after instruction-like log text is capped and marked for human confirmation. See [its threat model](10-ai-analyst-mcp/docs/THREAT_MODEL.md).
- Velociraptor queries take host, client and artifact names as query parameters, never as VQL text. Sigma rule values are escaped for `LIKE` and every time window is a bind parameter.
- Spreadsheet exports defang cells that start with `=`, `+`, `-` or `@`.
- Model output can never suppress high-criticality assets on its own.
- Markdown reports escape HTML and table delimiters.
