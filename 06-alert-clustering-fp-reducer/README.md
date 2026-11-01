# 06 · Alert clustering and false-positive reducer

> Part of the [Threat Response Engineering portfolio](../README.md). This folder is self-contained and can also be published as its own repository.

A triage engine that sits between the SIEM and the ticketing system. It takes a day of raw alerts and hands the analyst a short, ranked queue:

1. **Deduplicate** near-identical alerts into meta-alerts with TF-IDF and cosine-distance DBSCAN (K-Means is available for comparison).
2. **Enrich** each meta-alert from a SQLite CMDB: OS, listening services, role, business criticality, internet exposure, authorised scanners and maintenance windows.
3. **Filter false positives**, first with deterministic checks (for example, an RDP exploit against a Linux web server that does not listen on 3389 cannot succeed) and then with Claude for the clusters the rules cannot decide.
4. **Report** a prioritised Markdown and JSON queue. Every suppression comes with its evidence.

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The business case, with cited industry figures and a simulated ROI table, is in [docs/OPERATIONAL_EFFICIENCY_REPORT.md](docs/OPERATIONAL_EFFICIENCY_REPORT.md).

> **Scope.** This is a purely defensive triage tool. It reads alert metadata (rule names, addresses, ports, severities) that a SIEM has already produced. It never generates traffic, payloads or exploit content. The built-in generator produces simulated alert records only, using RFC 1918 and RFC 5737 documentation addresses.

## Quick start

```bash
cd 06-alert-clustering-fp-reducer
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # optional: add ANTHROPIC_API_KEY to enable Claude

export PYTHONPATH=src
python -m alert_triage init-cmdb --seed examples/cmdb_seed.yml
python -m alert_triage generate --count 5000 --out examples/alerts_simulated.json
python -m alert_triage triage --alerts examples/alerts_simulated.json \
    --report out/queue.md --json out/queue.json
python -m alert_triage evaluate --alerts examples/alerts_simulated.json --min-recall 1.0
```

```
INFO alert_triage: 5000 alerts -> 48 distinct documents -> 19 meta-alerts
5000 alerts -> 19 meta-alerts -> queue of 10 (6 escalate, 4 investigate); 3752 alerts suppressed; est. analyst time saved 99.4%
```

The rendered offline-mode output is in [examples/output/queue.md](examples/output/queue.md).

With Docker:

```bash
docker build -t alert-triage .
docker run --rm -v triage-data:/data --env-file .env alert-triage init-cmdb
docker run --rm -v triage-data:/data -v "$PWD/out:/out" -v "$PWD/examples:/in:ro" --env-file .env alert-triage \
    triage --alerts /in/alerts_simulated.json --report /out/queue.md
```

The CMDB and the verdict cache live in `/data`, so both commands mount the same named volume.

## Dispositions

| Reason | Disposition | Decided by | Rule |
|---|---|---|---|
| `AUTHORIZED_SCANNER` | suppress | CMDB | Every source address is inside a registered scanner range |
| `MAINTENANCE_WINDOW` | suppress | CMDB | Every target is in a change window for the whole cluster |
| `STRUCTURAL_FP` | suppress | CMDB + `config/signature_requirements.yml` | Every target is a known asset that lacks the OS, port or product the attack needs |
| `LLM_FALSE_POSITIVE` / `LLM_BENIGN` | suppress | Claude + guardrail | Confidence ≥ 0.8, no asset of criticality ≥ 4, severity below critical, every target known |
| `…_UNCONFIRMED` | investigate | guardrail | The model said FP or benign, but a guardrail condition failed |
| `LLM_TRUE_POSITIVE` / `RULES_TRUE_POSITIVE` | escalate | Claude / offline rules | Plausible attack against a real asset |
| `NEEDS_REVIEW` | investigate | Claude / offline rules | Not enough evidence either way, or targets missing from the CMDB |

**Offline mode.** Without `ANTHROPIC_API_KEY`, or when the API fails, the offline rules rank the queue. Their confidence never reaches the suppression floor, so they cannot hide anything. In the example run, the Citrix-against-nginx cluster stays escalated in offline mode because no requirement covers it. With Claude, that cluster is recognised as a structural mismatch, and the report suggests a new requirement for it under **Suggested applicability rules**.

## Input formats

- A JSON array, an `{"alerts": [...]}` object, or NDJSON.
- Generic SIEM fields: `timestamp`, `rule`, `severity`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `signature`, `category`.
- ECS fields, nested or dotted: `@timestamp`, `rule.name`, `event.severity`, `source.ip`, `destination.ip`, `destination.port`, `message`.

Project 01's ECS alerts can be fed in directly.

## Teaching it your estate

- **CMDB.** Edit `examples/cmdb_seed.yml`, or generate the YAML from your real CMDB or asset-discovery export. Then run `init-cmdb`. Services are what makes port and product checks possible. An asset with no service inventory is only judged on its OS.
- **Requirements.** Add to `config/signature_requirements.yml` a regex for the rule or signature, plus what it requires (`os_family`, `ports`, `products`). Log4Shell-style "any JVM" bugs are deliberately excluded, because embedded libraries are not reliably inventoried.

## Configuration

All settings are environment variables. The full list is in [.env.example](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | empty | Enables Claude. It is read by the SDK and never logged |
| `TRIAGE_LLM_MODEL` | `claude-opus-5-5` | Model for false-positive analysis |
| `TRIAGE_LLM_MIN_CONFIDENCE` | `0.8` | Floor for a model-only suppression |
| `TRIAGE_DBSCAN_EPS` | `0.3` | Cosine distance for merging (0.3 = at least 70% similar) |
| `TRIAGE_TIME_WINDOW_S` | `3600` | A quiet gap longer than this starts a new meta-alert |
| `TRIAGE_MINUTES_PER_RAW_ALERT` / `_META_ALERT` | `4` / `12` | Assumptions for the analyst-time estimate |

## Tests

```bash
pytest --cov      # 97 tests, 99% coverage, gate 85%
```

The suite covers:

- Alert normalisation for generic and ECS records, the ECS severity scale and every file format.
- Clustering: behaviour tokens, sweep handling for scans, near-duplicate merging, time-gap sessions and K-Means with silhouette.
- The CMDB: seeding, validation, scanner CIDRs, timezone-safe maintenance windows and the verdict cache.
- Applicability, including "no service inventory is not immunity".
- Every deterministic check and every guardrail, including partial matches that must *not* suppress.
- The Claude triager against a mocked client: request shape, structured output, refusals, `max_tokens`, malformed output, auth and transient errors, the circuit breaker, the blocking token bucket and the cache.
- Report rendering, including Markdown and HTML escaping of attacker-controlled text.
- CLI exit codes and an end-to-end run that requires 100% true-threat recall.

## Project layout

```text
06-alert-clustering-fp-reducer/
├── src/alert_triage/
│   ├── cli.py             `init-cmdb`, `generate`, `triage` and `evaluate` subcommands
│   ├── alerts.py          alert loading and normalisation
│   ├── cluster.py         TF-IDF documents and DBSCAN / k-means clustering
│   ├── cmdb.py            SQLite mock CMDB and verdict cache
│   ├── applicability.py   structural "can this attack even work here?" rules
│   ├── assess.py          triage decisions and guardrails
│   ├── llm.py             Claude triage, offline triager, rate limit, circuit breaker
│   ├── generator.py       labelled simulated alerts
│   ├── report.py          metrics and Markdown/JSON queue
│   └── config.py
├── config/signature_requirements.yml
├── examples/              CMDB seed, 5,000 simulated alerts and sample outputs
├── tests/                 pytest suite
├── docs/                  ARCHITECTURE.md and the operational efficiency report
├── Dockerfile
└── .env.example
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt ruff
ruff check .            # lint, using this folder's ruff.toml (includes security rules)
pytest --cov            # tests with the 85% coverage gate
```

Every module, class and public function has a docstring explaining what it does,
its arguments and the errors it raises. Start reading at `docs/ARCHITECTURE.md`,
then the entry point named in the layout above.

CI (`.github/workflows/ci.yml`) runs lint and tests on Python 3.10 and 3.13,
`pip-audit` on the runtime dependencies, and a non-root Docker build.

## Licence

MIT. See [LICENSE](LICENSE).
