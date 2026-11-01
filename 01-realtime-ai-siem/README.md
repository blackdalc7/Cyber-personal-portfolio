# 01 · Real-Time AI-SIEM

> Part of the [Threat Response Engineering portfolio](../README.md). This folder is self-contained and can also be published as its own repository.

A real-time UDP syslog SIEM. It receives RFC 5424 and RFC 3164 syslog as it arrives and maps every event strictly to **Elastic Common Schema 8.11**. Streaming detections cover brute force, successful compromise, password spraying and post-compromise privilege activity. Related alerts are linked into chains, and **Claude** summarises each chain for a Tier-1 analyst. Output goes to NDJSON files managed by `logging.handlers.RotatingFileHandler`.

The design rationale is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start

```bash
cd 01-realtime-ai-siem
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env          # optional: add ANTHROPIC_API_KEY for live Claude summaries

# terminal 1: start the receiver
PYTHONPATH=src python -m realtime_siem --port 5514

# terminal 2: replay a real attack (brute force → login → sudo → useradd) over UDP
PYTHONPATH=src python -m realtime_siem.replay tests/fixtures/auth.log --port 5514
```

You can also point a real syslog daemon at it:

```bash
logger --udp --server 127.0.0.1 --port 5514 --rfc5424 "Failed password for root from 203.0.113.9 port 22 ssh2"
# rsyslog: *.* @127.0.0.1:5514;RSYSLOG_SyslogProtocol23Format
```

Docker:

```bash
docker build -t realtime-siem .
docker run --rm -p 5514:5514/udp -v "$PWD/data:/data" --env-file .env realtime-siem
```

## Output

| File | Contents |
|---|---|
| `data/events.ndjson` | Every datagram as an ECS event (`event.kind: event`) |
| `data/alerts.ndjson` | Detection alerts (`event.kind: alert`, `rule.*`, `threat.*`) |
| `data/chains.ndjson` | Correlated chains with the AI summary, verdict, attack stage and actions (`siem.chain.*`) |
| `data/siem.log` | Application diagnostics and periodic stats |

Each stream rotates at `SIEM_ROTATE_MAX_BYTES` and keeps `SIEM_ROTATE_BACKUP_COUNT` backups.

Example chain summary (offline mode):

```json
{"@timestamp":"2026-10-26T11:08:59.000Z","event":{"kind":"alert","severity":99,...},
 "source":{"ip":"203.0.113.66"},
 "siem":{"chain":{"alert_count":4,"verdict":"True Positive","attack_stage":"post_compromise",
   "rule_ids":["SIEM-AUTH-001","SIEM-AUTH-002","SIEM-PRIV-001"],
   "summary":"203.0.113.66 brute forced and then logged in to web01, followed by privileged activity ...",
   "llm":{"provider":"offline","model":"rules-v1"}}}}
```

## Configuration

All settings come from environment variables or `.env`. See [`.env.example`](.env.example) for the full list with comments. The main ones:

| Variable | Default | Purpose |
|---|---|---|
| `SYSLOG_BIND_HOST` / `SYSLOG_BIND_PORT` | `0.0.0.0` / `5514` | Listener address |
| `SYSLOG_ALLOWED_SOURCES` | *(all)* | CIDR allow-list for senders |
| `SIEM_ROTATE_MAX_BYTES` / `SIEM_ROTATE_BACKUP_COUNT` | 50 MiB / 10 | Disk cap per stream |
| `DETECT_*` | see file | Detection thresholds and windows |
| `LLM_PROVIDER` | auto | `anthropic` or `offline`. Auto picks `anthropic` when `ANTHROPIC_API_KEY` is set |
| `LLM_MODEL` / `LLM_EFFORT` | `claude-opus-5-5` / `medium` | Claude model and effort level |
| `LLM_REDACT` | `false` | Pseudonymise usernames and hostnames before calling the API |

## Tests

```bash
pytest --cov            # 88 tests, coverage gate 85%
```

The suite covers:

- RFC parsing edge cases: SD escaping, nil values, year rollover, time zones and malformed input.
- ECS mapping, with the strict validator rejecting unknown fields, bad types and non-ECS values.
- Every detection rule, including windows, cooldowns and LRU memory bounds.
- Chain correlation and escalation.
- The Claude integration against a fake client: request shape, structured output, refusals, typed errors, the circuit breaker, rate limiting, redaction and prompt-fence escaping.
- Rotation behaviour.
- End-to-end runs over a **real UDP socket**, plus the CLI as a subprocess.

`test_live_claude_summary` calls the real API. It is skipped unless a real `ANTHROPIC_API_KEY` is set.

## Project layout

```text
01-realtime-ai-siem/
├── src/realtime_siem/
│   ├── server.py          asyncio UDP listener, bounded queue, CLI entry point
│   ├── syslog_parser.py   RFC 5424 / RFC 3164 / BSD syslog parsing
│   ├── ecs.py             mapping to ECS 8.11 and the strict schema validator
│   ├── detections.py      streaming brute-force, spraying, compromise and privilege rules
│   ├── correlation.py     groups alerts into per-source chains
│   ├── llm.py             Claude chain summaries, offline fallback, rate limit, circuit breaker
│   ├── pipeline.py        parse → normalise → detect → correlate → write
│   ├── sinks.py           rotating NDJSON output files
│   ├── replay.py          replays a log file over UDP for demos and tests
│   └── config.py          settings from environment variables / .env
├── tests/                 pytest suite (fixtures/auth.log is a recorded attack)
├── docs/ARCHITECTURE.md   design decisions and limits
├── Dockerfile             non-root container image
├── .env.example           every setting, with empty secrets
└── requirements*.txt      runtime and dev dependencies
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
